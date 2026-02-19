<?php
declare(strict_types=1);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

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
