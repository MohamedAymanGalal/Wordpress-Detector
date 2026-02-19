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

$rawUrl = isset($_GET['url']) ? trim((string)$_GET['url']) : '';
if ($rawUrl === '') {
    fail(400, 'Missing url parameter');
}

$parts = @parse_url($rawUrl);
if (!$parts || !isset($parts['scheme'], $parts['host'])) {
    fail(400, 'Invalid URL');
}

$scheme = strtolower((string)$parts['scheme']);
if ($scheme !== 'http' && $scheme !== 'https') {
    fail(400, 'Only http/https URLs are allowed');
}

$host = strtolower((string)$parts['host']);
if ($host === 'localhost' || str_ends_with($host, '.local')) {
    fail(403, 'Blocked host');
}

$ips = @gethostbynamel($host);
if (!$ips || !is_array($ips)) {
    fail(502, 'DNS lookup failed');
}

// Block private/reserved networks to reduce SSRF risk.
foreach ($ips as $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        fail(403, 'Blocked destination');
    }
}

$ch = curl_init($rawUrl);
if ($ch === false) {
    fail(500, 'Failed to initialize request');
}

curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 5,
    CURLOPT_CONNECTTIMEOUT => 8,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_USERAGENT => 'WP Inspector Proxy/1.0',
    CURLOPT_ENCODING => '',
    CURLOPT_HTTPHEADER => [
        'Accept: text/html,application/xhtml+xml,application/xml,application/json,text/plain,*/*',
    ],
]);

$body = curl_exec($ch);
if ($body === false) {
    $err = curl_error($ch);
    curl_close($ch);
    fail(502, 'Upstream fetch failed: ' . $err);
}

$statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
$contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
curl_close($ch);

http_response_code($statusCode > 0 ? $statusCode : 200);
if ($contentType !== '') {
    header('Content-Type: ' . $contentType);
} else {
    header('Content-Type: text/plain; charset=utf-8');
}

echo $body;
