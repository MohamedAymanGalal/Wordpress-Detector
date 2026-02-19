<?php
declare(strict_types=1);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Optional local config fallback (not committed): define('WPSCAN_API_TOKEN', '...');
@include_once __DIR__ . '/config.php';

function fail(int $status, string $message): void
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message;
    exit;
}

function fetch_remote(string $url, array $headers = [], int $connectTimeout = 8, int $timeout = 25): array
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('Failed to initialize request');
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_CONNECTTIMEOUT => $connectTimeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => 'WP Inspector Proxy/1.0',
        CURLOPT_ENCODING => '',
        CURLOPT_HTTPHEADER => $headers,
    ]);

    $body = curl_exec($ch);
    if ($body === false) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('Upstream fetch failed: ' . $err);
    }

    $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    return [
        'status' => $statusCode > 0 ? $statusCode : 200,
        'content_type' => $contentType,
        'body' => $body,
    ];
}

function fetch_headers_only(string $url, int $connectTimeout = 6, int $timeout = 10): array
{
    $collected = [];
    $setCookies = [];
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('Failed to initialize request');
    }

    curl_setopt_array($ch, [
        CURLOPT_NOBODY => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_CONNECTTIMEOUT => $connectTimeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => 'WP Inspector Proxy/1.0',
        CURLOPT_HEADERFUNCTION => static function ($ch, $line) use (&$collected, &$setCookies) {
            $trim = trim($line);
            if ($trim === '' || strpos($trim, ':') === false) {
                return strlen($line);
            }
            [$name, $value] = explode(':', $trim, 2);
            $key = strtolower(trim($name));
            $val = trim($value);
            if ($key === 'set-cookie') {
                $setCookies[] = $val;
            } else {
                if (!isset($collected[$key])) {
                    $collected[$key] = $val;
                } else {
                    $collected[$key] .= ', ' . $val;
                }
            }
            return strlen($line);
        },
        CURLOPT_RETURNTRANSFER => true,
    ]);

    $ok = curl_exec($ch);
    if ($ok === false) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('Header fetch failed: ' . $err);
    }
    $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $effectiveUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);

    return [
        'status' => $statusCode > 0 ? $statusCode : 200,
        'final_url' => $effectiveUrl !== '' ? $effectiveUrl : $url,
        'headers' => $collected,
        'set_cookie' => $setCookies,
    ];
}

function block_private_destinations(string $host): void
{
    $host = strtolower($host);
    if ($host === 'localhost' || str_ends_with($host, '.local')) {
        fail(403, 'Blocked host');
    }

    $ips = @gethostbynamel($host);
    if (!$ips || !is_array($ips)) {
        fail(502, 'DNS lookup failed');
    }

    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            fail(403, 'Blocked destination');
        }
    }
}

// Dedicated vulnerability lookup endpoint (WPScan API v3).
if (isset($_GET['action']) && $_GET['action'] === 'wpvuln') {
    $token = getenv('WPSCAN_API_TOKEN');
    if (!$token && defined('WPSCAN_API_TOKEN')) {
        $token = (string) WPSCAN_API_TOKEN;
    }
    if (!$token) {
        fail(503, 'WPScan API token is not configured');
    }

    $type = isset($_GET['type']) ? trim((string) $_GET['type']) : '';
    $path = null;
    if ($type === 'core') {
        $version = isset($_GET['version']) ? trim((string) $_GET['version']) : '';
        if ($version === '' || !preg_match('/^[0-9]+(\.[0-9]+){0,3}$/', $version)) {
            fail(400, 'Invalid core version');
        }
        $path = '/wordpresses/' . rawurlencode($version);
    } elseif ($type === 'plugin' || $type === 'theme') {
        $slug = isset($_GET['slug']) ? trim((string) $_GET['slug']) : '';
        if ($slug === '' || !preg_match('/^[a-z0-9_-]+$/i', $slug)) {
            fail(400, 'Invalid component slug');
        }
        $path = '/' . ($type === 'plugin' ? 'plugins' : 'themes') . '/' . rawurlencode(strtolower($slug));
    } else {
        fail(400, 'Invalid vulnerability lookup type');
    }

    $apiUrl = 'https://wpscan.com/api/v3' . $path;
    try {
        $result = fetch_remote(
            $apiUrl,
            [
                'Accept: application/json',
                'Authorization: Token token=' . $token,
            ],
            8,
            18
        );
    } catch (Throwable $e) {
        fail(502, $e->getMessage());
    }

    http_response_code($result['status']);
    header('Content-Type: application/json; charset=utf-8');
    echo $result['body'];
    exit;
}

// Server-side PageSpeed endpoint to avoid exposing API keys in frontend.
if (isset($_GET['action']) && $_GET['action'] === 'pagespeed') {
    $targetUrl = isset($_GET['url']) ? trim((string) $_GET['url']) : '';
    if ($targetUrl === '') {
        fail(400, 'Missing url parameter');
    }
    $parts = @parse_url($targetUrl);
    if (!$parts || !isset($parts['scheme'], $parts['host'])) {
        fail(400, 'Invalid URL');
    }
    $scheme = strtolower((string) $parts['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') {
        fail(400, 'Only http/https URLs are allowed');
    }

    $psiToken = getenv('GOOGLE_PAGESPEED_API_KEY');
    if (!$psiToken) {
        $psiToken = getenv('PSI_API_KEY');
    }
    if (!$psiToken && defined('GOOGLE_PAGESPEED_API_KEY')) {
        $psiToken = (string) GOOGLE_PAGESPEED_API_KEY;
    }
    if (!$psiToken && defined('PSI_API_KEY')) {
        $psiToken = (string) PSI_API_KEY;
    }
    if (!$psiToken) {
        fail(503, 'PageSpeed API key is not configured');
    }

    $apiUrl = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed'
        . '?url=' . rawurlencode($targetUrl)
        . '&key=' . rawurlencode($psiToken)
        . '&category=performance&category=accessibility&category=best-practices&category=seo';

    try {
        $result = fetch_remote(
            $apiUrl,
            ['Accept: application/json'],
            8,
            25
        );
    } catch (Throwable $e) {
        fail(502, $e->getMessage());
    }

    http_response_code($result['status']);
    header('Content-Type: application/json; charset=utf-8');
    echo $result['body'];
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'headers') {
    $targetUrl = isset($_GET['url']) ? trim((string) $_GET['url']) : '';
    if ($targetUrl === '') {
        fail(400, 'Missing url parameter');
    }
    $parts = @parse_url($targetUrl);
    if (!$parts || !isset($parts['scheme'], $parts['host'])) {
        fail(400, 'Invalid URL');
    }
    $scheme = strtolower((string) $parts['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') {
        fail(400, 'Only http/https URLs are allowed');
    }
    block_private_destinations((string) $parts['host']);

    try {
        $result = fetch_headers_only($targetUrl, 6, 10);
    } catch (Throwable $e) {
        fail(502, $e->getMessage());
    }

    http_response_code($result['status']);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status' => $result['status'],
        'final_url' => $result['final_url'],
        'headers' => $result['headers'],
        'set_cookie' => $result['set_cookie'],
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'mailcheck') {
    $rawDomain = isset($_GET['domain']) ? trim((string) $_GET['domain']) : '';
    if ($rawDomain === '') {
        fail(400, 'Missing domain parameter');
    }

    $rawDomain = preg_replace('#^https?://#i', '', $rawDomain);
    $rawDomain = preg_replace('#/.*$#', '', (string) $rawDomain);
    $rawDomain = preg_replace('/:\d+$/', '', (string) $rawDomain);
    $rawDomain = strtolower(trim((string) $rawDomain, " \t\n\r\0\x0B."));
    if ($rawDomain === '' || !preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $rawDomain)) {
        fail(400, 'Invalid domain');
    }

    block_private_destinations($rawDomain);

    $result = [
        'domain' => $rawDomain,
        'mx' => ['ok' => false, 'records' => []],
        'spf' => ['ok' => false, 'record' => null, 'issues' => []],
        'dmarc' => ['ok' => false, 'record' => null, 'policy' => null, 'pct' => null, 'rua' => null],
        'dkim' => ['ok' => false, 'found_selectors' => [], 'checked_selectors' => []],
    ];

    $mxRecords = @dns_get_record($rawDomain, DNS_MX);
    if (is_array($mxRecords)) {
        $rows = [];
        foreach ($mxRecords as $mx) {
            if (!isset($mx['target'])) {
                continue;
            }
            $rows[] = [
                'host' => (string) $mx['target'],
                'pri' => isset($mx['pri']) ? (int) $mx['pri'] : null,
            ];
        }
        usort($rows, static function (array $a, array $b): int {
            return (int) ($a['pri'] ?? 0) <=> (int) ($b['pri'] ?? 0);
        });
        $result['mx']['records'] = $rows;
        $result['mx']['ok'] = count($rows) > 0;
    }

    $txtRecords = @dns_get_record($rawDomain, DNS_TXT);
    if (is_array($txtRecords)) {
        $spf = null;
        foreach ($txtRecords as $txt) {
            $v = isset($txt['txt']) ? (string) $txt['txt'] : (isset($txt['entries'][0]) ? (string) $txt['entries'][0] : '');
            if ($v !== '' && stripos($v, 'v=spf1') === 0) {
                $spf = $v;
                break;
            }
        }
        if ($spf !== null) {
            $result['spf']['record'] = $spf;
            $result['spf']['ok'] = true;
            if (stripos($spf, '+all') !== false) {
                $result['spf']['issues'][] = 'SPF uses +all (too permissive)';
            }
            if (!preg_match('/[~-]all\b/i', $spf)) {
                $result['spf']['issues'][] = 'SPF missing explicit all mechanism';
            }
            if (stripos($spf, '?all') !== false) {
                $result['spf']['issues'][] = 'SPF uses ?all (neutral)';
            }
            if (stripos($spf, '~all') !== false) {
                $result['spf']['issues'][] = 'SPF uses softfail (~all)';
            }
        }
    }

    $dmarcDomain = '_dmarc.' . $rawDomain;
    $dmarcTxt = @dns_get_record($dmarcDomain, DNS_TXT);
    if (is_array($dmarcTxt)) {
        foreach ($dmarcTxt as $txt) {
            $v = isset($txt['txt']) ? (string) $txt['txt'] : (isset($txt['entries'][0]) ? (string) $txt['entries'][0] : '');
            if ($v !== '' && stripos($v, 'v=DMARC1') === 0) {
                $result['dmarc']['ok'] = true;
                $result['dmarc']['record'] = $v;
                if (preg_match('/\bp=([a-z]+)/i', $v, $m)) {
                    $result['dmarc']['policy'] = strtolower((string) $m[1]);
                }
                if (preg_match('/\bpct=(\d{1,3})/i', $v, $m)) {
                    $result['dmarc']['pct'] = (int) $m[1];
                }
                if (preg_match('/\brua=([^;]+)/i', $v, $m)) {
                    $result['dmarc']['rua'] = trim((string) $m[1]);
                }
                break;
            }
        }
    }

    $selectors = ['default', 'selector1', 'selector2', 'google', 'k1', 'mail', 'smtp'];
    $result['dkim']['checked_selectors'] = $selectors;
    $found = [];
    foreach ($selectors as $sel) {
        $dkimHost = $sel . '._domainkey.' . $rawDomain;
        $dkimTxt = @dns_get_record($dkimHost, DNS_TXT);
        if (!is_array($dkimTxt) || count($dkimTxt) === 0) {
            continue;
        }
        foreach ($dkimTxt as $txt) {
            $v = isset($txt['txt']) ? (string) $txt['txt'] : (isset($txt['entries'][0]) ? (string) $txt['entries'][0] : '');
            if ($v !== '' && stripos($v, 'v=DKIM1') !== false) {
                $found[] = $sel;
                break;
            }
        }
    }
    $result['dkim']['found_selectors'] = $found;
    $result['dkim']['ok'] = count($found) > 0;

    http_response_code(200);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($result, JSON_UNESCAPED_SLASHES);
    exit;
}

// Generic URL proxy mode used by scanner fetches.
$rawUrl = isset($_GET['url']) ? trim((string) $_GET['url']) : '';
if ($rawUrl === '') {
    fail(400, 'Missing url parameter');
}

$parts = @parse_url($rawUrl);
if (!$parts || !isset($parts['scheme'], $parts['host'])) {
    fail(400, 'Invalid URL');
}

$scheme = strtolower((string) $parts['scheme']);
if ($scheme !== 'http' && $scheme !== 'https') {
    fail(400, 'Only http/https URLs are allowed');
}

$host = (string) $parts['host'];
block_private_destinations($host);

try {
    $result = fetch_remote(
        $rawUrl,
        ['Accept: text/html,application/xhtml+xml,application/xml,application/json,text/plain,*/*'],
        8,
        30
    );
} catch (Throwable $e) {
    fail(502, $e->getMessage());
}

http_response_code($result['status']);
if ($result['content_type'] !== '') {
    header('Content-Type: ' . $result['content_type']);
} else {
    header('Content-Type: text/plain; charset=utf-8');
}
echo $result['body'];
