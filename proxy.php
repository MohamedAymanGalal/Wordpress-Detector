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
        CURLOPT_HEADERFUNCTION => static function ($ch, $line) use (&$collected) {
            $trim = trim($line);
            if ($trim === '' || strpos($trim, ':') === false) {
                return strlen($line);
            }
            [$name, $value] = explode(':', $trim, 2);
            $key = strtolower(trim($name));
            $val = trim($value);
            if (!isset($collected[$key])) {
                $collected[$key] = $val;
            } else {
                $collected[$key] .= ', ' . $val;
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
    curl_close($ch);

    return [
        'status' => $statusCode > 0 ? $statusCode : 200,
        'headers' => $collected,
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
    echo json_encode(['headers' => $result['headers']], JSON_UNESCAPED_SLASHES);
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
