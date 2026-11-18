<?php
@ini_set('display_errors', '0');
@ini_set('max_execution_time', '0');
@set_time_limit(0);
@ignore_user_abort(true);
error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE & ~E_DEPRECATED);
define('ECHO_HOST', 'cloudflare.com');
define('ECHO_PATH', '/');
define('TRACE_TIMEOUT', 5);
define('TLS_RETRY_TIMEOUT_MS', 5000);
define('TLS_RETRY_COUNT', 0);
define('MAX_RESPONSE_BYTES', 65536);
define('SLOW_RESPONSE_MS', 9999);
define('GENERIC_FAIL_REASON', '远端返回失败结果');
define('TLS_VERIFY_CERT', true);
define('BROWSER_UA', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36');
$ECHO_HOSTS = array(ECHO_HOST);
define('MAX_TARGETS_PER_REQUEST', 50);
define('MAX_IPS_PER_FAMILY', 9999);
define('MAX_TARGETS_PER_DOMAIN', 9999);
$CF_CIDR_V4 = array(
  '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
  '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
  '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
  '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22'
);
$CF_CIDR_V6 = array(
  '2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32',
  '2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32'
);
function isValidIPv4($ip) {
  return $ip !== '' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}
function isValidIPv6Strict($ip) {
  if ($ip === '' || strpos($ip, ':') === false) return false;
  if (stripos($ip, '::ffff:') === 0) return false;
  if (preg_match('/[^0-9a-fA-F:.]/', $ip)) return false;
  return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}
function ipFamily($ip) {
  $ip = trim((string)$ip);
  if ($ip === '') return null;
  if (isValidIPv4($ip)) return 'ipv4';
  if (stripos($ip, '::ffff:') === 0) {
    $rest = substr($ip, 7);
    if (isValidIPv4($rest)) return 'ipv4';
    return null;
  }
  if (isValidIPv6Strict($ip)) return 'ipv6';
  return null;
}
function classifyHost($host) {
  $f = ipFamily($host);
  if ($f === 'ipv4') return 'ipv4';
  if ($f === 'ipv6') return 'ipv6';
  return 'domain';
}
function displayHost($host, $family) {
  return $family === 'ipv6' ? '[' . $host . ']' : $host;
}
function isValidPort($port) {
  $n = (int)$port;
  return (string)$n === (string)$port || is_numeric($port)
    ? ($n >= 1 && $n <= 65535 && (int)$port == $port)
    : false;
}
function parseHostPort($addr, $defaultPort = 443) {
  $host = $addr; $port = $defaultPort;
  if ($addr !== '' && $addr[0] === '[') {
    $close = strpos($addr, ']');
    if ($close !== false) {
      $host = substr($addr, 1, $close - 1);
      $rest = substr($addr, $close + 1);
      if (strpos($rest, ':') === 0) $port = substr($rest, 1);
    }
  } else {
    $colonCount = substr_count($addr, ':');
    if ($colonCount > 1) {
      $host = $addr;
    } elseif ($colonCount === 1) {
      $idx = strrpos($addr, ':');
      $host = substr($addr, 0, $idx);
      $port = substr($addr, $idx + 1);
    }
  }
  $portInt = is_numeric((string)$port) ? (int)$port : $defaultPort;
  return array(trim($host), $portInt);
}
function ipv4ToInt($ip) {
  $l = ip2long($ip);
  if ($l === false) return 0;
  return (int)sprintf('%u', $l);
}
function isInCidrV4($ip, $cidr) {
  $parts = explode('/', $cidr);
  $bits = (int)$parts[1];
  if ($bits === 0) return true;
  $mask = $bits === 32 ? 0xffffffff : ((0xffffffff << (32 - $bits)) & 0xffffffff);
  return (ipv4ToInt($ip) & $mask) === (ipv4ToInt($parts[0]) & $mask);
}
function isInCidrV6($ip, $cidr) {
  $parts = explode('/', $cidr);
  $bits = (int)$parts[1];
  if ($bits === 0) return true;
  $a = @inet_pton($ip);
  $b = @inet_pton($parts[0]);
  if ($a === false || $b === false || strlen($a) !== 16 || strlen($b) !== 16) return false;
  $full = (int)($bits / 8);
  $rem = $bits % 8;
  for ($i = 0; $i < $full; $i++) {
    if ($a[$i] !== $b[$i]) return false;
  }
  if ($rem > 0) {
    $mask = (0xff << (8 - $rem)) & 0xff;
    if ((ord($a[$full]) & $mask) !== (ord($b[$full]) & $mask)) return false;
  }
  return true;
}
function isCloudflareOwnedIp($ip) {
  global $CF_CIDR_V4, $CF_CIDR_V6;
  $f = ipFamily($ip);
  if ($f === 'ipv4') {
    foreach ($CF_CIDR_V4 as $c) { if (isInCidrV4($ip, $c)) return true; }
  } elseif ($f === 'ipv6') {
    foreach ($CF_CIDR_V6 as $c) { if (isInCidrV6($ip, $c)) return true; }
  }
  return false;
}
function getServerPublicIp() {
  static $cached = null;
  static $done = false;
  if ($done) return $cached;
  $done = true;
  $body = '';
  $url = 'https://' . ECHO_HOST . ECHO_PATH;
  if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_USERAGENT, BROWSER_UA);
    $body = curl_exec($ch);
    curl_close($ch);
    if ($body === false) $body = '';
  } else {
    $ctx = stream_context_create(array('http' => array('timeout' => 5, 'header' => "User-Agent: " . BROWSER_UA . "\r\nAccept: application/json\r\n")));
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) $body = '';
  }
  if ($body !== '') {
    $d = json_decode($body, true);
    if (is_array($d) && !empty($d['ip'])) $cached = trim((string)$d['ip']);
  }
  return $cached;
}
function dohOne($name, $typeInt) {
  $url = 'https://cloudflare-dns.com/dns-query?name=' . rawurlencode($name) . '&type=' . $typeInt;
  $body = '';
  if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/dns-json'));
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
    $body = curl_exec($ch);
    curl_close($ch);
    if ($body === false || $body === '') return array();
  } else {
    $ctx = stream_context_create(array('http' => array(
      'method' => 'GET', 'timeout' => 5,
      'header' => "Accept: application/dns-json\r\n",
    ), 'ssl' => array('verify_peer' => true, 'verify_peer_name' => true)));
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false || $body === '') return array();
  }
  $data = json_decode($body, true);
  if (!is_array($data) || empty($data['Answer']) || !is_array($data['Answer'])) return array();
  return $data['Answer'];
}
function dohQuery($name, $type, $depth = 0) {
  $types = array('A' => 1, 'AAAA' => 28, 'TXT' => 16);
  $want = $types[$type];
  $collected = array();
  $cname = null;
  $list = dohOne($name, $want);
  foreach ($list as $a) {
    if (!isset($a['type'])) continue;
    if ((int)$a['type'] === $want) {
      $v = $type === 'TXT'
        ? str_replace('"', '', (string)(isset($a['data']) ? $a['data'] : ''))
        : trim((string)(isset($a['data']) ? $a['data'] : ''));
      if ($v !== '') $collected[$v] = true;
    } elseif ((int)$a['type'] === 5 && !empty($a['data']) && $cname === null) {
      $cname = rtrim((string)$a['data'], '.');
    }
  }
  if (empty($collected) && $cname !== null && $depth < 3) return dohQuery($cname, $type, $depth + 1);
  return array_keys($collected);
}
function resolveDomain($name) {
  return array(
    'v4' => dohQuery($name, 'A'),
    'txt' => dohQuery($name, 'TXT'),
  );
}
function parseTargetSpec($raw) {
  $text = trim((string)$raw);
  $explicitSni = null;
  $hash = strpos($text, '#');
  if ($hash !== false) {
    $after = trim(substr($text, $hash + 1));
    $parts = preg_split('/[\?\s]/', $after);
    $explicitSni = ($parts && $parts[0] !== '') ? $parts[0] : null;
    $text = substr($text, 0, $hash);
  }
  $text = preg_replace('/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//', '', $text);
  $q = strpos($text, '?');
  if ($q !== false) $text = substr($text, 0, $q);
  $at = strrpos($text, '@');
  if ($at !== false) $text = substr($text, $at + 1);
  return array('target' => trim($text), 'sni' => $explicitSni);
}
function parseTxtHosts($records, $defaultPort) {
  $out = array(); $seen = array();
  foreach ((array)$records as $rec) {
    $text = trim(str_replace('"', '', (string)$rec), "\" \t\n\r\0\x0B");
    if ($text === '') continue;
    $toks = preg_split('/[\s,;|#]+/', $text);
    foreach ($toks as $tok) {
      if ($tok === '') continue;
      list($h, $p) = parseHostPort($tok, $defaultPort);
      if ($h === '' || !isValidPort($p)) continue;
      $kind = classifyHost($h);
      if ($kind === 'domain' && !preg_match('/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/', $h)) continue;
      $key = strtolower($h) . '|' . $p;
      if (isset($seen[$key])) continue;
      $seen[$key] = true;
      $out[] = array('host' => $h, 'port' => (int)$p, 'family' => $kind);
    }
  }
  return $out;
}
function expandTarget($raw) {
  $spec = parseTargetSpec($raw);
  $trimmed = $spec['target'];
  $explicitSni = $spec['sni'];
  if ($trimmed === '') return array();
  list($host, $port) = parseHostPort($trimmed, 443);
  if ($host === '' || !isValidPort($port)) return array();
  $kind = classifyHost($host);
  if ($kind === 'ipv6') return array();
  if ($kind !== 'domain') {
    return array(array('host' => $host, 'port' => (int)$port, 'input' => $raw, 'family' => $kind,
      'isDomain' => false, 'sniHost' => $explicitSni, 'hostHeader' => $explicitSni));
  }
  $r = resolveDomain($host);
  $targets = array(); $seen = array();
  $push = function ($h, $p, $family, $source) use (&$targets, &$seen, $trimmed, $host, $explicitSni) {
    if (!isValidPort($p)) return;
    $key = $h . '|' . $p;
    if (isset($seen[$key]) || count($targets) >= MAX_TARGETS_PER_DOMAIN) return;
    $seen[$key] = true;
    $targets[] = array('host' => $h, 'port' => (int)$p, 'input' => $trimmed, 'family' => $family,
      'isDomain' => true, 'domain' => $host, 'source' => $source,
      'sniHost' => $explicitSni, 'hostHeader' => $explicitSni);
  };
  $v4 = array_values(array_filter($r['v4'], 'isValidIPv4'));
  foreach (array_slice($v4, 0, MAX_IPS_PER_FAMILY) as $ip) $push($ip, $port, 'ipv4', 'A');
  foreach (parseTxtHosts($r['txt'], $port) as $t) {
    if ($t['family'] === 'ipv6') continue;
    $push($t['host'], $t['port'], $t['family'], 'TXT');
  }
  if (empty($targets)) {
    return array(array('host' => $host, 'port' => (int)$port, 'input' => $trimmed, 'family' => 'hostname',
      'isDomain' => true, 'domain' => $host, 'viaHostname' => true,
      'sniHost' => $explicitSni, 'hostHeader' => $explicitSni));
  }
  return $targets;
}
function parseJsonProbe($body) {
  $data = json_decode($body, true);
  if (!is_array($data)) return array('ok' => false);
  $outIp = trim((string)(isset($data['ip']) ? $data['ip'] : ''));
  $colo = strtoupper(trim((string)(isset($data['colo']) ? $data['colo'] : '')));
  if ($outIp === '') return array('ok' => false);
  if (!preg_match('/^[A-Z]{3}$/', $colo)) return array('ok' => false);
  $outType = ipFamily($outIp);
  if ($outType === null) return array('ok' => false);
  return array('ok' => true, 'colo' => $colo, 'outIp' => $outIp, 'outType' => $outType, 'fields' => $data);
}
function parsePlainIpProbe($body) {
  $body = trim($body);
  if ($body === '') return array('ok' => false);
  $lines = preg_split('/\r?\n/', $body);
  $ip = trim($lines[0]);
  if (strpos($ip, '<') !== false || strpos($ip, ' ') !== false) return array('ok' => false);
  $fam = ipFamily($ip);
  if ($fam === null) return array('ok' => false);
  return array('ok' => true, 'colo' => '', 'outIp' => $ip, 'outType' => $fam, 'fields' => array());
}
function dechunkHttp($body) {
  $out = ''; $pos = 0; $len = strlen($body);
  while ($pos < $len) {
    $eol = strpos($body, "\r\n", $pos);
    if ($eol === false) break;
    $sizeHex = trim(substr($body, $pos, $eol - $pos));
    $semi = strpos($sizeHex, ';');
    if ($semi !== false) $sizeHex = substr($sizeHex, 0, $semi);
    $size = hexdec($sizeHex);
    if ($size === 0) break;
    $pos = $eol + 2;
    $out .= substr($body, $pos, $size);
    $pos += $size + 2;
  }
  return $out;
}
function systemCaBundle() {
  static $found = null;
  if ($found !== null) return $found;
  $found = '';
  foreach (array(
    '/usr/local/share/certs/ca-root-nss.crt',
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/ssl/cert.pem',
    '/usr/local/etc/openssl/cert.pem',
    '/etc/pki/tls/certs/ca-bundle.crt',
  ) as $p) { if (is_file($p)) { $found = $p; break; } }
  return $found;
}
function doTlsProbe($host, $port, $sniHost, $hostHeader, $path, $opts = array()) {
  $isPlain = !empty($opts['plainIp']);
  $retries = isset($opts['retries']) ? (int)$opts['retries'] : TLS_RETRY_COUNT;
  $startedAt = microtime(true);
  for ($attempt = 0; $attempt <= $retries; $attempt++) {
    $attemptStart = microtime(true);
    $handshakeTimeout = ($attempt === 0) ? TRACE_TIMEOUT : (int)(TLS_RETRY_TIMEOUT_MS / 1000);
    if ($handshakeTimeout < 1) $handshakeTimeout = 1;
    $fp = null;
    $isV6 = (classifyHost($host) === 'ipv6');
    $remote = $isV6 ? 'tls://[' . $host . ']:' . $port : 'tls://' . $host . ':' . $port;
    $peer = $sniHost ? $sniHost : $hostHeader;
    $sslOpts = array(
      'SNI_enabled' => true,
      'peer_name' => $peer,
      'verify_peer' => TLS_VERIFY_CERT,
      'verify_peer_name' => TLS_VERIFY_CERT,
      'allow_self_signed' => !TLS_VERIFY_CERT,
      'capture_peer_cert' => true,
      'crypto_method' => STREAM_CRYPTO_METHOD_TLS_CLIENT,
    );
    if (TLS_VERIFY_CERT) {
      $ca = systemCaBundle();
      if ($ca !== '') $sslOpts['cafile'] = $ca;
    }
    $ctx = stream_context_create(array('ssl' => $sslOpts));
    $errno = 0; $errstr = '';
    $fp = @stream_socket_client($remote, $errno, $errstr, $handshakeTimeout, STREAM_CLIENT_CONNECT, $ctx);
    if ($fp === false) {
      if ($attempt < $retries) { usleep((80 + $attempt * 120) * 1000); continue; }
      break;
    }
    stream_set_blocking($fp, true);
    stream_set_timeout($fp, TRACE_TIMEOUT);
    $accept = $isPlain ? '*/*' : 'application/json';
    $req = 'GET ' . $path . " HTTP/1.1\r\n"
      . 'Host: ' . $hostHeader . "\r\n"
      . 'User-Agent: ' . BROWSER_UA . "\r\n"
      . 'Accept: ' . $accept . "\r\n"
      . "Connection: close\r\n\r\n";
    $w = @fwrite($fp, $req);
    if ($w === false) {
      @fclose($fp);
      if ($attempt < $retries) { usleep((80 + $attempt * 120) * 1000); continue; }
      break;
    }
    $raw = '';
    $deadline = $attemptStart + TRACE_TIMEOUT;
    $headerEnd = -1; $status = 0; $contentType = '';
    $contentLength = -1; $isChunked = false; $headersOk = false; $headersBad = false;
    $badBodyDeadline = null;
    while (microtime(true) < $deadline && strlen($raw) <= MAX_RESPONSE_BYTES) {
      $waitEnd = ($headersBad && $badBodyDeadline !== null) ? min($deadline, $badBodyDeadline) : $deadline;
      if (microtime(true) >= $waitEnd) break;
      $remaining = $waitEnd - microtime(true);
      stream_set_timeout($fp, (int)ceil($remaining));
      $chunk = @fread($fp, 8192);
      if ($chunk === false || $chunk === '') break;
      $raw .= $chunk;
      if ($headerEnd < 0) {
        $pos = strpos($raw, "\r\n\r\n");
        if ($pos !== false) {
          $headerEnd = $pos;
          $headerStr = substr($raw, 0, $pos);
          if (!preg_match('/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i', $headerStr, $m)) {
            $headersBad = true; $badBodyDeadline = microtime(true) + 2;
          } else {
            $status = (int)$m[1];
            if ($status !== 200) {
              $headersBad = true; $badBodyDeadline = microtime(true) + 2;
            } else {
              if (preg_match('/^content-type:\s*([^\r\n]+)/im', $headerStr, $m)) $contentType = trim($m[1]);
              if (!$isPlain) {
                if ($contentType === '') { $headersBad = true; $badBodyDeadline = microtime(true) + 2; }
                elseif (!preg_match('/^application\/json(\s*;|$)/i', $contentType)) { $headersBad = true; $badBodyDeadline = microtime(true) + 2; }
              }
              if (!$headersBad) {
                if (preg_match('/^content-length:\s*(\d+)\s*$/im', $headerStr, $m)) $contentLength = (int)$m[1];
                if (preg_match('/^transfer-encoding:.*chunked/im', $headerStr)) $isChunked = true;
                $headersOk = true;
              }
            }
          }
        }
      }
      if ($headersBad) {
        if ($headerEnd >= 0 && (strlen($raw) - $headerEnd - 4) >= 300) break;
        continue;
      }
      if ($headersOk) {
        $bodyLen = strlen($raw) - $headerEnd - 4;
        if ($isChunked) {
          if (strpos($raw, "\r\n0\r\n\r\n", $headerEnd) !== false) break;
        } elseif ($contentLength >= 0) {
          if ($bodyLen >= $contentLength) break;
        } else {
          if ($bodyLen > 0) break;
        }
      }
    }
    @fclose($fp);
    if ($headerEnd < 0) {
      if ((microtime(true) - $attemptStart) >= TRACE_TIMEOUT && $attempt < $retries) {
        usleep((80 + $attempt * 100) * 1000); continue;
      }
      return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
    }
    if ($headersBad) {
      return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
    }
    if ((microtime(true) - $attemptStart) > TRACE_TIMEOUT) {
      if ($attempt < $retries) { usleep((80 + $attempt * 100) * 1000); continue; }
      return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
    }
    if (strlen($raw) > MAX_RESPONSE_BYTES) return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
    $body = substr($raw, $headerEnd + 4);
    if ($contentLength >= 0) $body = substr($body, 0, $contentLength);
    elseif ($isChunked) $body = dechunkHttp($body);
    if ($isPlain) $probe = parsePlainIpProbe($body);
    else $probe = parseJsonProbe($body);
    if (empty($probe['ok'])) {
      return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
    }
    return array(
      'ok' => true, 'colo' => $probe['colo'], 'outIp' => $probe['outIp'], 'outType' => $probe['outType'],
      'sameFamilyAsTarget' => ($probe['outIp'] === $host),
      'fields' => isset($probe['fields']) ? $probe['fields'] : array(),
      'cost' => (int)round((microtime(true) - $startedAt) * 1000),
      'attempts' => $attempt + 1,
    );
  }
  return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
}
function singleProbe($host, $port, $selfHost, $targetSniHost = null, $targetHostHeader = null) {
  if (!$selfHost) return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
  $sni = $targetSniHost ? $targetSniHost : $selfHost;
  $hostHeader = $targetHostHeader ? $targetHostHeader : $sni;
  return doTlsProbe($host, $port, $sni, $hostHeader, ECHO_PATH);
}
function probeFamilies($host, $port, $main) {
  $found = array('v4' => '', 'v6' => '');
  if ($main['outType'] === 'ipv4') $found['v4'] = $main['outIp'];
  if ($main['outType'] === 'ipv6') $found['v6'] = $main['outIp'];
  if ($found['v4'] === '') {
    $r = doTlsProbe($host, $port, 'ipv4.icanhazip.com', 'ipv4.icanhazip.com', '/', array('plainIp' => true, 'retries' => 0));
    if (!empty($r['ok']) && $r['outType'] === 'ipv4') $found['v4'] = $r['outIp'];
  }
  return $found;
}
function probeTarget($host, $port, $targetSniHost = null, $targetHostHeader = null) {
  global $ECHO_HOSTS;
  $isOfficialCfIp = isCloudflareOwnedIp($host);
  $hosts = $targetSniHost ? array($targetSniHost) : $ECHO_HOSTS;
  $probe = null;
  foreach ($hosts as $echoHost) {
    $probe = singleProbe($host, $port, $echoHost, $targetSniHost, $targetHostHeader);
    if (!empty($probe['ok'])) break;
    return array('ok' => false, 'reason' => !empty($probe['reason']) ? $probe['reason'] : GENERIC_FAIL_REASON);
  }
  if ($probe === null || empty($probe['ok'])) {
    return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
  }
  if ($probe['cost'] > SLOW_RESPONSE_MS) {
    return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
  }
  $serverIp = getServerPublicIp();
  if ($serverIp !== null && $serverIp !== '' && $probe['outIp'] === $serverIp) {
    return array('ok' => false, 'reason' => GENERIC_FAIL_REASON);
  }
  $fam = probeFamilies($host, $port, $probe);
  $dual = !empty($fam['v4']) && !empty($fam['v6']);
  $f = isset($probe['fields']) ? $probe['fields'] : array();
  $outAsn = isset($f['asn']) ? (string)$f['asn'] : '';
  $outOrg = isset($f['asOrganization']) ? (string)$f['asOrganization'] : '';
  $outCountry = isset($f['country']) ? (string)$f['country'] : '';
  return array('ok' => true, 'result' => array(
    'ip' => displayHost($host, ipFamily($host) === 'ipv6' ? 'ipv6' : 'ipv4'),
    '端口' => (int)$port,
    '出口ip' => $probe['outIp'],
    '出口类型' => $probe['outType'],
    '出口IPv4' => $fam['v4'],
    '出口IPv6' => $fam['v6'],
    '双栈' => $dual,
    '数据中心' => $probe['colo'],
    '国家' => $outCountry !== '' ? $outCountry : '未知',
    '地区' => (isset($f['region']) && $f['region'] !== '') ? (string)$f['region'] : '未知',
    '城市' => (isset($f['city']) && $f['city'] !== '') ? (string)$f['city'] : '未知',
    '响应时间' => $probe['cost'] . 'ms',
    '出口国家' => $outCountry,
    '出口地区' => (isset($f['region']) && $f['region'] !== '') ? (string)$f['region'] : '',
    '出口地区代码' => isset($f['regionCode']) ? $f['regionCode'] : '',
    '出口城市' => (isset($f['city']) && $f['city'] !== '') ? (string)$f['city'] : '',
    'ASN' => $outAsn,
    '组织' => $outOrg,
    '出口地址与目标是否同族一致' => $probe['sameFamilyAsTarget'],
    '是否为Cloudflare官方IP' => $isOfficialCfIp,
    '有效ProxyIP' => true,
  ));
}
function jsonOut($data) {
  if (!headers_sent()) {
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
  }
  echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}
function requestPath() {
  $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
  $q = strpos($uri, '?');
  if ($q !== false) $uri = substr($uri, 0, $q);
  return $uri;
}
if (requestPath() === '/__proxyip_echo' || (isset($_GET['echo']) && $_GET['echo'] === '1')) {
  $rip = '';
  if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) $rip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
  elseif (!empty($_SERVER['HTTP_TRUE_CLIENT_IP'])) $rip = trim($_SERVER['HTTP_TRUE_CLIENT_IP']);
  elseif (!empty($_SERVER['REMOTE_ADDR'])) $rip = trim($_SERVER['REMOTE_ADDR']);
  $rip = explode(',', $rip);
  $rip = trim($rip[0]);
  jsonOut(array(
    'ip' => $rip, 'colo' => '', 'country' => '', 'region' => '', 'regionCode' => '',
    'city' => '', 'asn' => '', 'asOrganization' => '', 'httpProtocol' => '',
    'tlsVersion' => '', 'ts' => time(), 'server' => 'serv00-php',
    'note' => '本地回显仅供状态显示，检测走 ' . ECHO_HOST . ' /（090227 JSON 回显）',
  ));
}
if (isset($_GET['backend']) && $_GET['backend'] === '1') {
  $echoUrl = 'https://' . ECHO_HOST . ECHO_PATH;
  $body = '';
  if (function_exists('curl_init')) {
    $ch = curl_init($echoUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/json'));
    curl_setopt($ch, CURLOPT_USERAGENT, BROWSER_UA);
    $body = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($body === false || $body === '' || $http !== 200) $body = '';
  } else {
    $ctx = stream_context_create(array('http' => array(
      'timeout' => 5, 'header' => "Accept: application/json\r\nUser-Agent: " . BROWSER_UA . "\r\n",
    )));
    $body = @file_get_contents($echoUrl, false, $ctx);
    if ($body === false) $body = '';
  }
  $d = null;
  if ($body !== '') {
    $jd = json_decode($body, true);
    if (is_array($jd) && !empty($jd['ip']) && !empty($jd['colo'])) {
      $d = array('ip' => (string)$jd['ip'], 'colo' => strtoupper((string)$jd['colo']),
        'country' => isset($jd['country']) ? (string)$jd['country'] : '');
    }
  }
  if (!is_array($d) || empty($d['colo'])) {
    if (!headers_sent()) {
      header('Content-Type: application/json; charset=utf-8');
      http_response_code(502);
    }
    echo json_encode(array('error' => 'backend echo unavailable'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
  }
  $d['echo_host'] = ECHO_HOST;
  $d['source'] = '090227';
  jsonOut($d);
}
if (isset($_GET['ip']) && trim((string)$_GET['ip']) !== '') {
  $ipParam = trim((string)$_GET['ip']);
  if (isset($_GET['resolve']) && $_GET['resolve'] === '1') {
    $parts = explode(',', $ipParam);
    $list = expandTarget($parts[0]);
    $jobs = array();
    foreach ($list as $t) {
      $jobs[] = array(
        'host' => $t['host'], 'port' => (int)$t['port'],
        'addr' => $t['family'] === 'ipv6' ? '[' . $t['host'] . ']:' . $t['port'] : $t['host'] . ':' . $t['port'],
        'family' => $t['family'], 'isDomain' => !empty($t['isDomain']),
        'domain' => isset($t['domain']) ? $t['domain'] : '',
        'source' => isset($t['source']) ? $t['source'] : '',
        'viaHostname' => !empty($t['viaHostname']),
        'input' => $t['input'], 'sni' => isset($t['sniHost']) ? $t['sniHost'] : '',
        'label' => !empty($t['isDomain'])
          ? $t['domain'] . ' -> ' . displayHost($t['host'], $t['family']) . ':' . $t['port']
          : displayHost($t['host'], $t['family']) . ':' . $t['port'],
      );
    }
    jsonOut($jobs);
  }
  if (isset($_GET['direct']) && $_GET['direct'] === '1') {
    $parts = explode(',', $ipParam);
    $spec = parseTargetSpec($parts[0]);
    list($dHost, $dPort) = parseHostPort($spec['target'], 443);
    $dSni = (isset($_GET['sni']) && $_GET['sni'] !== '') ? $_GET['sni'] : $spec['sni'];
    $targets = ($dHost !== '' && isValidPort($dPort))
      ? array(array('host' => $dHost, 'port' => (int)$dPort, 'input' => $spec['target'],
          'family' => classifyHost($dHost), 'isDomain' => false, 'sniHost' => $dSni, 'hostHeader' => $dSni))
      : array();
  } else {
    $targets = array();
    foreach (explode(',', $ipParam) as $raw) {
      foreach (expandTarget($raw) as $t) $targets[] = $t;
      if (count($targets) >= MAX_TARGETS_PER_REQUEST) break;
    }
    $targets = array_slice($targets, 0, MAX_TARGETS_PER_REQUEST);
  }
  if (empty($targets)) jsonOut(array());
  $output = array();
  foreach ($targets as $t) {
    $o = probeTarget($t['host'], $t['port'],
      isset($t['sniHost']) ? $t['sniHost'] : null,
      isset($t['hostHeader']) ? $t['hostHeader'] : null);
    $targetLabel = !empty($t['isDomain'])
      ? $t['domain'] . ' -> ' . displayHost($t['host'], $t['family']) . ':' . $t['port']
      : displayHost($t['host'], $t['family']) . ':' . $t['port'];
    $row = array('目标' => $targetLabel);
    if (!empty($t['isDomain'])) {
      $row['输入'] = $t['input'];
      $row['解析地址族'] = strtoupper($t['family']);
      if (!empty($t['source'])) $row['解析来源'] = $t['source'];
    }
    if (!empty($o['ok'])) {
      $row['有效ProxyIP'] = true;
      foreach ($o['result'] as $k => $v) $row[$k] = $v;
    } else {
      $row['有效ProxyIP'] = false;
      $row['失败原因'] = isset($o['reason']) ? $o['reason'] : GENERIC_FAIL_REASON;
      if (!empty($t['viaHostname']) && $row['失败原因'] === GENERIC_FAIL_REASON) {
        $row['失败原因'] = 'DoH 未解析到 A/TXT 记录，直连域名探测也失败：' . GENERIC_FAIL_REASON;
      }
    }
    $output[] = $row;
  }
  jsonOut($output);
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
<meta name="color-scheme" content="dark" />
<meta name="theme-color" content="#090b31" />
<meta name="description" content="CFProxy-Web：Cloudflare ProxyIP 单个与批量检测工具，支持结果筛选和导出。" />
<title>CFProxy Web · Check ProxyIP</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%23c084fc'/%3E%3Cstop offset='.5' stop-color='%238b5cf6'/%3E%3Cstop offset='1' stop-color='%2338bdf8'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='16' fill='url(%23g)'/%3E%3Cg transform='translate(12 12) scale(1.67)'%3E%3Cpath d='M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z' fill='%23fff'/%3E%3Cpath d='M12 16V10M9.2 12.8L12 10l2.8 2.8' stroke='%238b5cf6' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' fill='none'/%3E%3C/g%3E%3C/svg%3E" />
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0b0716;
    --bg-panel:rgba(26,18,54,.72);
    --bg-elevated:rgba(43,29,88,.55);
    --border:rgba(167,139,250,.32);
    --border-soft:rgba(167,139,250,.17);
    --text:#f3eefc;
    --text-dim:#b8a9de;
    --text-faint:#7d6da6;
    --accent:#a78bfa;
    --accent-soft:rgba(139,92,246,.13);
    --warn:#fbbf24;
    --warn-soft:rgba(251,191,36,.13);
    --danger:#fb7185;
    --danger-soft:rgba(251,113,133,.13);
    --info:#7dd3fc;
    --radius:10px;
    --sans:'IBM Plex Sans', system-ui, -apple-system, 'Segoe UI', sans-serif;
    --mono:'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  *{box-sizing:border-box}
  html,body{margin:0;padding:0}
  body{
    position:relative;
    isolation:isolate;
    min-height:100vh;
    background:
      radial-gradient(900px 520px at 88% -8%, rgba(124,58,237,.38), transparent 62%),
      radial-gradient(760px 460px at -12% 18%, rgba(59,130,246,.30), transparent 62%),
      radial-gradient(640px 520px at 50% 112%, rgba(236,72,153,.16), transparent 62%),
      var(--bg);
    color:var(--text);
    font-family:var(--sans);
    line-height:1.55;
    -webkit-font-smoothing:antialiased;
  }
  body::before{
    content:"";
    position:fixed;
    inset:0;
    z-index:-1;
    pointer-events:none;
    transform:translateZ(0);
  }
  ::selection{background:var(--accent-soft);color:var(--accent)}
  a{color:var(--info)}
  [hidden]{display:none !important}
  .wrap{
    max-width:760px;margin:0 auto;
    padding:clamp(32px,7vw,64px) clamp(16px,4vw,20px) clamp(32px,6vw,48px);
    padding-left:max(clamp(16px,4vw,20px), env(safe-area-inset-left, 0px));
    padding-right:max(clamp(16px,4vw,20px), env(safe-area-inset-right, 0px));
  }
  .hero{
    position:relative;
    margin-bottom:28px;
    min-height:clamp(300px,38vw,410px);
    padding:clamp(22px,4vw,38px);
    display:flex;
    flex-direction:column;
    justify-content:center;
    border:1px solid rgba(190,160,255,.28);
    border-radius:22px;
    background:linear-gradient(105deg,rgba(12,7,31,.48) 0%,rgba(18,10,43,.30) 52%,rgba(18,10,43,.10) 100%);
    box-shadow:0 18px 54px rgba(4,2,18,.24),0 0 38px rgba(124,58,237,.10) inset;
    backdrop-filter:blur(1px);
    -webkit-backdrop-filter:blur(1px);
    overflow:hidden;
  }
  .hero > *{position:relative;z-index:1}
  .hero h3{max-width:48ch;color:#e7ddff;font-size:clamp(14px,2vw,16px);font-weight:400;line-height:1.75;margin:16px 0 0;text-shadow:0 2px 12px rgba(0,0,0,.55)}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--text-faint);flex:none}
  .dot.live{background:var(--accent);box-shadow:0 0 0 0 var(--accent-soft);animation:pulse 1.8s infinite}
  @keyframes pulse{
    0%{box-shadow:0 0 0 0 rgba(139,92,246,.45)}
    70%{box-shadow:0 0 0 7px rgba(139,92,246,0)}
    100%{box-shadow:0 0 0 0 rgba(139,92,246,0)}
  }
  .dot.warn{background:var(--warn);animation:pulse-warn 1.8s infinite}
  @keyframes pulse-warn{
    0%{box-shadow:0 0 0 0 rgba(251,191,36,.45)}
    70%{box-shadow:0 0 0 7px rgba(251,191,36,0)}
    100%{box-shadow:0 0 0 0 rgba(251,191,36,0)}
  }
  .dot.error{background:var(--danger);animation:none}
  .hero h1{
    font-size:clamp(22px,4.2vw,28px);line-height:1.32;font-weight:600;letter-spacing:-.01em;
    margin:0 0 12px;max-width:24ch;
  }
  .hero p{color:var(--text-dim);font-size:clamp(13.5px,2.6vw,15px);margin:0;max-width:56ch}
  .panel{
    background:var(--bg-panel);border:1px solid var(--border);
    border-radius:var(--radius);padding:22px 22px 20px;margin-bottom:18px;
    backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
    box-shadow:0 10px 34px rgba(8,4,24,.45), 0 0 0 1px rgba(255,255,255,.03) inset;
  }
  .panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px;flex-wrap:wrap}
  .panel-head h2{font-size:14.5px;font-weight:600;margin:0;color:var(--text)}
  .mode-switch{display:flex;background:var(--bg-elevated);border:1px solid var(--border);border-radius:8px;padding:3px;gap:2px}
  .mode-btn{
    font-family:var(--sans);font-size:13px;color:var(--text-dim);background:transparent;border:0;
    padding:6px 13px;border-radius:6px;cursor:pointer;transition:color .15s, background .15s;
  }
  .mode-btn.active{background:var(--bg);color:var(--text)}
  .mode-btn:hover:not(.active){color:var(--text)}
  #input-single{display:flex;flex-direction:column;gap:10px}
  #singleInput, #batchInput{
    width:100%;background:var(--bg-elevated);border:1px solid var(--border);
    color:var(--text);font-family:var(--mono);font-size:14px;
    border-radius:8px;padding:11px 12px;outline:none;transition:border-color .15s, background .15s;
  }
  #singleInput:focus, #batchInput:focus{border-color:var(--accent)}
  #singleInput.input-error{border-color:var(--danger)}
  #batchInput{
    display:block;
    min-height:240px;
    max-height:70vh;
    resize:vertical;
    line-height:1.7;
    white-space:pre;
    overflow:auto;
    tab-size:4;
  }
  #batchInput.drag-over{border-color:var(--accent);background:var(--accent-soft)}
  #input-batch{display:flex;flex-direction:column;gap:10px}
  .batch-tools{
    display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;
  }
  .batch-count{font-family:var(--mono);font-size:12.5px;color:var(--text-faint)}
  .batch-count b{color:var(--accent);font-weight:600}
  .batch-count .warn{color:var(--warn)}
  .batch-btns{display:flex;gap:8px;flex-wrap:wrap}
  .hint{font-size:12.5px;color:var(--text-faint)}
  .hint.error{color:var(--danger)}
  .btn-primary{
    font-family:var(--sans);font-weight:600;font-size:13.5px;color:#160a2e;
    background:linear-gradient(135deg,#c084fc 0%,#8b5cf6 42%,#6366f1 72%,#38bdf8 100%);border:0;border-radius:8px;padding:9px 18px;color:#fff;box-shadow:0 0 18px rgba(139,92,246,.55), 0 4px 16px rgba(99,102,241,.35);
    cursor:pointer;transition:filter .15s, transform .1s;white-space:nowrap;
  }
  .btn-primary:hover{filter:brightness(1.12);box-shadow:0 0 26px rgba(139,92,246,.75), 0 4px 20px rgba(99,102,241,.45)}
  .btn-primary:active{transform:translateY(1px)}
  .btn-primary:disabled{opacity:.5;cursor:default;filter:none}
  .btn-ghost{
    font-family:var(--sans);font-size:12.5px;color:var(--text-dim);
    background:transparent;border:1px solid var(--border);border-radius:7px;
    padding:6px 11px;cursor:pointer;transition:color .15s, border-color .15s;
  }
  .btn-ghost:hover{color:var(--text);border-color:var(--text-faint)}
  .status-pill{
    font-family:var(--mono);font-size:14px;font-weight:600;padding:5px 12px;border-radius:999px;
    background:var(--bg-elevated);color:var(--text-dim);border:1px solid var(--border);
  }
  .status-pill.running{color:var(--warn);border-color:rgba(251,191,36,.35)}
  .status-pill.done{color:#4ade80;border-color:rgba(74,222,128,.45);background:rgba(74,222,128,.12)}
  .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
  .stat{
    background:var(--bg-elevated);border:1px solid var(--border-soft);border-radius:8px;
    padding:13px 14px;
  }
  .stat-num{display:block;font-family:var(--mono);font-size:22px;font-weight:600;line-height:1.1;color:var(--text)}
  .stat-label{display:block;font-size:12px;color:var(--text-faint);margin-top:4px}
  .stat.good .stat-num{color:var(--accent)}
  .stat.pending .stat-num{color:var(--warn)}
  .stat.bad .stat-num{color:var(--danger)}
  .export-row{display:flex;gap:8px;flex-wrap:wrap}
  .filter-box{
    background:var(--bg-elevated);border:1px solid var(--border-soft);border-radius:9px;
    padding:14px 16px;margin-bottom:14px;display:flex;flex-direction:column;gap:12px;
  }
  .filter-summary{font-size:14px;color:var(--text-dim)}
  .filter-summary b{color:var(--text);font-weight:600}
  .filter-row{display:flex;align-items:flex-start;gap:12px}
  .filter-label{
    flex:none;width:34px;padding-top:6px;font-size:12.5px;font-weight:600;color:var(--text-faint);
  }
  .filter-chips{display:flex;flex-wrap:wrap;gap:8px;min-width:0}
  .filter-chip{
    font-family:var(--sans);font-size:12.5px;font-weight:500;color:var(--text-dim);
    background:var(--bg-panel);border:1px solid var(--border);border-radius:999px;
    padding:5px 13px;cursor:pointer;white-space:nowrap;transition:color .15s, border-color .15s, background .15s;
  }
  .filter-chip:hover:not(:disabled):not(.active){color:var(--text);border-color:var(--text-faint)}
  .filter-chip.active{background:var(--accent-soft);color:var(--accent);border-color:rgba(139,92,246,.5)}
  .filter-chip:disabled{opacity:.35;cursor:default}
  .results-list{display:flex;flex-direction:column;gap:10px}
  .result-card{
    border:1px solid var(--border-soft);border-radius:12px;background:var(--bg-elevated);
    padding:18px 20px;min-width:0;
  }
  .result-card.ok{border-left:3px solid var(--accent)}
  .result-card.fail{border-left:3px solid var(--danger)}
  .result-card.loading{border-left:3px solid var(--text-faint)}
  .rc-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
  .rc-target{font-family:var(--mono);font-size:15px;color:var(--text);word-break:break-all}
  .rc-target.copyable{cursor:pointer;transition:color .15s;-webkit-user-select:none;user-select:none}
  .rc-target.copyable:hover{color:var(--accent)}
  .rc-target.copyable.copied{color:var(--accent)}
  .rc-field-value.copyable{cursor:pointer;transition:color .15s;-webkit-user-select:none;user-select:none}
  .rc-field-value.copyable:hover{color:var(--accent)}
  .rc-field-value.copyable.copied{color:var(--accent)}
  .rc-sub{font-family:var(--mono);font-size:11.5px;color:var(--text-faint);margin-top:2px}
  .badge{font-family:var(--mono);font-size:13px;font-weight:600;padding:4px 10px;border-radius:999px;white-space:nowrap;flex:none}
  .badge.ok{background:rgba(74,222,128,.16);color:#4ade80;border:1px solid rgba(74,222,128,.4)}
  .badge.fail{background:rgba(251,113,133,.20);color:#fb7185;border:1px solid rgba(251,113,133,.45)}
  .badge.loading{background:var(--bg);color:var(--text-faint)}
  .rc-fields{
    display:grid;grid-template-columns:repeat(4,minmax(0,1fr));
    column-gap:22px;row-gap:16px;margin-top:17px;min-width:0;
  }
  .rc-field{min-width:0}
  .rc-field-label{font-size:12px;color:var(--text-faint);line-height:1.45}
  .rc-field-value{
    font-family:var(--mono);font-size:14px;color:var(--text);
    line-height:1.55;margin-top:4px;overflow-wrap:anywhere;word-break:normal;
  }
  .rc-field-label.has-tip{border-bottom:1px dashed var(--text-faint);display:inline-block;cursor:help}
  .rc-reason{font-size:12.5px;color:var(--danger);margin-top:10px}
  .spinner{
    width:12px;height:12px;border-radius:50%;
    border:2px solid var(--border);border-top-color:var(--text-dim);
    animation:spin .7s linear infinite;flex:none;
  }
  @keyframes spin{to{transform:rotate(360deg)}}
  .toast-container{
    position:fixed;left:50%;bottom:24px;transform:translateX(-50%);
    z-index:9999;display:flex;flex-direction:column;gap:8px;
    align-items:center;pointer-events:none;
    padding-bottom:env(safe-area-inset-bottom, 0px);
  }
  .toast{
    font-family:var(--sans);font-size:13.5px;font-weight:500;color:var(--text);
    background:var(--bg-elevated);border:1px solid var(--border);
    border-radius:999px;padding:9px 18px;box-shadow:0 8px 24px rgba(0,0,0,.35);
    display:flex;align-items:center;gap:8px;white-space:nowrap;
    opacity:0;transform:translateY(8px);
    transition:opacity .18s ease, transform .18s ease;
  }
  .toast.show{opacity:1;transform:translateY(0)}
  .toast.success{border-color:rgba(139,92,246,.45)}
  .toast.success .toast-icon{color:var(--accent)}
  .toast.error{border-color:rgba(251,113,133,.45)}
  .toast.error .toast-icon{color:var(--danger)}
  .toast-icon{flex:none;font-size:14px;line-height:1}
  @media (max-width:600px){
    .toast{font-size:13px;padding:8px 15px;max-width:86vw;white-space:normal;text-align:center}
  }
  .guide h2{font-size:14.5px;font-weight:600;margin:0 0 16px}
  .guide-grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
  .guide-item h3{font-size:14px;font-weight:600;margin:0 0 6px;color:var(--text)}
  .guide-item p{font-size:13.5px;color:var(--text-dim);margin:0;max-width:62ch}
  .site-footer{
    margin-top:8px;padding-top:20px;border-top:1px solid var(--border-soft);
    font-size:12px;color:var(--text-faint);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
  }
  @media (min-width:1025px){
    body::before{background-position:center,center,58% 24%}
    .wrap{max-width:920px}
    .rc-fields{grid-template-columns:repeat(4,minmax(0,1fr));column-gap:22px}
    #batchInput{min-height:280px}
  }
  @media (min-width:601px) and (max-width:1024px){
    body::before{background-position:center,center,64% center}
    .wrap{max-width:760px}
    .hero{min-height:340px}
    .stat-grid{grid-template-columns:repeat(4,1fr);gap:8px}
    .stat{padding:11px 12px}
  }
  @media (max-width:600px){
    body::before{
      background-size:cover,cover,auto 100svh;
      background-position:center,center,64% top;
    }
    .wrap{padding-top:max(18px,env(safe-area-inset-top,0px));padding-bottom:max(28px,env(safe-area-inset-bottom,0px))}
    .hero{
      min-height:390px;
      padding:22px 18px;
      margin-bottom:18px;
      border-radius:18px;
      background:linear-gradient(100deg,rgba(9,5,25,.56) 0%,rgba(12,7,32,.34) 58%,rgba(12,7,32,.16) 100%);
    }
    .hero h3{font-size:13px;line-height:1.65;max-width:34ch}
    .panel{padding:16px 14px 14px}
    .stat-grid{grid-template-columns:repeat(2,1fr)}
    .panel-head{gap:10px}
    .export-row{flex-direction:column}
    .export-row .btn-ghost{width:100%;text-align:center}
    .rc-head{align-items:flex-start}
    .rc-fields{grid-template-columns:repeat(2,minmax(0,1fr))}
    #batchInput{min-height:200px}
    .batch-tools{flex-direction:column;align-items:stretch}
    .batch-btns .btn-ghost{flex:1;text-align:center}
  }
  @media (max-width:380px){
    .hero{min-height:360px;padding:18px 14px}
    .stat-grid{grid-template-columns:repeat(2,1fr);gap:8px}
    .stat-num{font-size:19px}
  }
  @media (hover:none) and (pointer:coarse){
    .btn-primary,.btn-ghost{min-height:42px}
    .mode-btn{min-height:36px;padding:8px 14px}
    #singleInput,#batchInput{font-size:16px}
  }
  @media (prefers-reduced-motion: reduce){
    .dot.live,.dot.warn{animation:none}
    .spinner{animation:none}
  }
  :root{
    --cf-violet:#a855f7;
    --cf-blue:#3b82f6;
    --cf-cyan:#38bdf8;
    --glass:rgba(24,18,62,.42);
    --glass-border:rgba(220,205,255,.36);
  }
  html{scroll-behavior:smooth;scroll-padding-top:24px}
  body{
    min-height:100vh;
    background:#070b2a;
    overflow-x:hidden;
  }
  body::before{
    background-image:
      linear-gradient(90deg,rgba(5,8,35,.42) 0%,rgba(8,9,42,.24) 39%,rgba(8,9,42,.04) 75%,rgba(8,9,42,.10) 100%),
      linear-gradient(180deg,rgba(5,7,28,.24) 0%,rgba(6,8,35,.03) 45%,rgba(8,8,42,.40) 100%),
      url("./cfdata-web-bg.webp");
    background-repeat:no-repeat;
    background-size:cover,cover,cover;
    background-position:center,center,center top;
    transform:translateZ(0);
  }
  .wrap{
    width:min(100% - 48px,1500px);
    max-width:1500px;
    padding:18px 0 44px;
    margin:0 auto;
  }
  .site-header{
    min-height:72px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:24px;
    padding:0 clamp(4px,1.5vw,22px);
    border-bottom:1px solid rgba(185,174,255,.14);
    background:linear-gradient(180deg,rgba(7,9,35,.46),rgba(7,9,35,.08));
    backdrop-filter:blur(8px);
    -webkit-backdrop-filter:blur(8px);
  }
  .site-brand{
    display:inline-flex;
    align-items:center;
    gap:12px;
    color:#fff;
    text-decoration:none;
    min-width:0;
  }
  .brand-cloud{
    display:grid;
    place-items:center;
    width:44px;height:44px;
    color:#fff;
    filter:drop-shadow(0 0 8px #5c8dff) drop-shadow(0 0 18px rgba(143,91,255,.75));
    flex:none;
  }
  .brand-cloud svg{width:100%;height:100%}
  .brand-name{
    font-size:clamp(19px,2vw,25px);
    font-weight:700;
    letter-spacing:-.035em;
    text-shadow:0 2px 14px rgba(0,0,0,.4);
  }
  .brand-name span{
    background:linear-gradient(100deg,#c084fc,#8b5cf6 55%,#60a5fa);
    -webkit-background-clip:text;background-clip:text;color:transparent;
  }
  .site-nav{display:flex;align-items:center;gap:12px}
  .nav-link{
    display:inline-flex;align-items:center;justify-content:center;gap:8px;
    min-height:38px;padding:7px 15px;border-radius:999px;
    color:#e9e5ff;text-decoration:none;font-size:13px;font-weight:600;
    background:rgba(85,91,178,.22);border:1px solid rgba(196,187,255,.16);
    transition:background .2s,border-color .2s,transform .2s;
  }
  .nav-link:hover{background:rgba(124,91,255,.34);border-color:rgba(196,187,255,.42);transform:translateY(-1px)}
  .nav-status{font-family:inherit;cursor:pointer}
  .nav-status svg{width:14px;height:14px;flex:none}
  .hero-stage{
    min-height:clamp(590px,70vw,760px);
    display:grid;
    grid-template-columns:minmax(0,1.12fr) minmax(0,.88fr);
    align-items:center;
    gap:clamp(16px,3vw,48px);
    padding:clamp(34px,5vw,76px) clamp(10px,2vw,28px) 28px;
  }
  .hero-content{position:relative;z-index:2;width:100%;max-width:850px}
  .hero{
    min-height:0;margin:0 0 32px;padding:0;
    display:block;overflow:visible;border:0;border-radius:0;
    background:transparent;box-shadow:none;
    backdrop-filter:none;-webkit-backdrop-filter:none;
  }
  .hero > *{position:static;z-index:auto}
  .hero h1{
    max-width:none;margin:0;
    color:#fff;font-size:clamp(48px,6.4vw,92px);
    line-height:.98;font-weight:800;letter-spacing:-.065em;
    text-shadow:0 4px 28px rgba(0,0,0,.38),0 0 34px rgba(126,100,255,.24);
  }
  .hero h1 span{
    background:linear-gradient(105deg,#d8b4fe 0%,#a855f7 48%,#60a5fa 100%);
    -webkit-background-clip:text;background-clip:text;color:transparent;
  }
  .hero-lead{
    margin:22px 0 0!important;max-width:none!important;
    color:#f4f1ff!important;font-size:clamp(19px,2.6vw,30px)!important;
    font-weight:600;letter-spacing:.015em;
    text-shadow:0 2px 18px rgba(0,0,0,.48);
  }
  .hero h3{
    display:flex;align-items:center;gap:14px;
    margin:18px 0 0;max-width:42ch;
    color:#d9d8ff;font-size:clamp(14px,1.55vw,18px);
    line-height:1.7;font-weight:400;
    text-shadow:0 2px 12px rgba(0,0,0,.56);
  }
  .hero h3::before,.hero h3::after{
    content:"";height:1px;flex:1;min-width:24px;
    background:linear-gradient(90deg,transparent,rgba(220,205,255,.55));
  }
  .hero h3::after{
    background:linear-gradient(90deg,rgba(220,205,255,.55),transparent);
  }
  #panel-input{
    width:100%;max-width:860px;
    padding:20px 22px 18px;margin:0;
    border:1px solid rgba(232,224,255,.42);
    border-radius:22px;
    background:linear-gradient(130deg,rgba(222,219,255,.23),rgba(81,70,169,.22) 58%,rgba(40,31,108,.30));
    box-shadow:0 18px 48px rgba(3,5,35,.30),0 0 34px rgba(141,108,255,.18) inset;
    backdrop-filter:blur(16px) saturate(145%);
    -webkit-backdrop-filter:blur(16px) saturate(145%);
  }
  #panel-input .mode-switch{
    width:100%;padding:4px;gap:4px;border-radius:12px;margin-bottom:16px;
    background:rgba(14,17,65,.30);border-color:rgba(225,219,255,.20);
  }
  #panel-input .mode-btn{
    flex:1;display:inline-flex;align-items:center;justify-content:center;gap:6px;
    padding:8px 13px;border-radius:9px;
    color:#e2dcff;font-size:13px;white-space:nowrap;
  }
  #panel-input .mode-btn.active{
    color:#fff;background:linear-gradient(135deg,#2563eb,#1d4ed8);
    box-shadow:0 4px 16px rgba(37,99,235,.45);
  }
  #panel-input .input-row{display:flex;align-items:flex-start;gap:12px}
  #panel-input .input-area{flex:1;min-width:0}
  #panel-input #singleInput{min-height:46px}
  #panel-input #runBtn{flex:none}
  #panel-input #inputHint{margin:12px 2px 0}
  #panel-history .history-list{display:flex;flex-direction:column;gap:8px}
  #panel-history .history-item{
    display:flex;align-items:center;gap:10px;width:100%;text-align:left;
    padding:10px 12px;border-radius:8px;cursor:pointer;
    color:#e9e5ff;background:rgba(28,30,92,.32);border:1px solid rgba(221,213,255,.26);
    font-family:var(--mono);font-size:13px;
  }
  #panel-history .history-item:hover{border-color:rgba(167,139,250,.6);background:rgba(40,42,110,.45)}
  #panel-history .history-item span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  #panel-history .history-item i{font-style:normal;color:#9ecbff;font-size:12px;flex:none}
  #singleInput,#batchInput{
    color:#17234e;
    background:rgba(245,247,255,.91);
    border:1px solid rgba(255,255,255,.76);
    box-shadow:0 4px 18px rgba(8,10,58,.12) inset;
  }
  #singleInput::placeholder,#batchInput::placeholder{color:#68739c}
  #singleInput:focus,#batchInput:focus{
    border-color:#9b8cff;box-shadow:0 0 0 3px rgba(167,139,250,.18);
  }
  #batchInput{min-height:180px}
  #panel-input .batch-count{color:#e4e1ff}
  #panel-input .batch-count b{color:#fff}
  #panel-input .hint{color:#e2ddff}
  #panel-input .btn-ghost{
    color:#fff;background:rgba(24,24,83,.28);
    border-color:rgba(228,220,255,.34);
  }
  #panel-input .btn-primary{
    min-height:46px;padding:11px 24px;border-radius:12px;
    font-size:15px;letter-spacing:.02em;
    background:linear-gradient(110deg,#c44df4 0%,#8054ff 48%,#168cff 100%);
    box-shadow:0 8px 24px rgba(92,76,255,.34),0 0 22px rgba(183,87,255,.28);
  }
  .hero-visual-space{min-height:360px}
  .feature-grid{
    display:grid;grid-template-columns:repeat(4,minmax(0,1fr));
    gap:clamp(12px,2vw,26px);
    padding:0 clamp(10px,2vw,28px) 36px;
    margin-top:-10px;
  }
  .feature-card{
    min-height:104px;display:flex;align-items:center;gap:15px;
    padding:17px 20px;border-radius:18px;
    border:1px solid rgba(225,216,255,.34);
    background:linear-gradient(130deg,rgba(232,225,255,.22),rgba(84,73,169,.23));
    box-shadow:0 12px 32px rgba(5,6,42,.18),0 0 22px rgba(154,119,255,.12) inset;
    backdrop-filter:blur(13px) saturate(145%);
    -webkit-backdrop-filter:blur(13px) saturate(145%);
  }
  .feature-icon{
    width:56px;height:56px;display:grid;place-items:center;flex:none;
    border-radius:50%;color:#c8f4ff;font-size:30px;font-weight:800;
    background:linear-gradient(145deg,#4c5fff,#0878ee);
    box-shadow:0 0 20px rgba(48,112,255,.45),0 0 0 5px rgba(83,115,255,.10);
    text-shadow:0 1px 8px rgba(255,255,255,.5);
  }
  .feature-copy{display:flex;flex-direction:column;gap:4px;min-width:0}
  .feature-copy b{font-size:17px;color:#fff;line-height:1.25}
  .feature-copy small{font-size:12px;color:#e1dcff;line-height:1.45}
  #panel-summary,#panel-results,.guide{
    background:rgba(15,14,52,.78);
    border-color:rgba(167,139,250,.34);
    box-shadow:0 16px 42px rgba(3,4,28,.28);
    backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  }
  .site-footer{color:#c1b8e8;border-color:rgba(191,174,255,.22)}
  @media (min-width:1500px){
    .hero-stage{min-height:760px}
  }
  @media (min-width:701px) and (max-width:1050px){
    .wrap{width:min(100% - 32px,1100px)}
    .hero-stage{
      min-height:620px;grid-template-columns:minmax(0,1fr) minmax(0,.55fr);
      padding-top:48px;gap:8px;
    }
    .hero h1{font-size:clamp(48px,7vw,70px)}
    #panel-input{padding:18px}
    .feature-grid{grid-template-columns:repeat(2,minmax(0,1fr));margin-top:0}
    .feature-card{min-height:88px}
  }
  @media (max-width:700px){
    body::before{
      background-image:
        linear-gradient(180deg,rgba(5,7,28,.20) 0%,rgba(6,8,35,.30) 44%,rgba(7,8,38,.84) 100%),
        url("./cfdata-web-bg-mobile.webp");
      background-size:cover,cover;
      background-position:center,center top;
    }
    .wrap{
      width:100%;max-width:none;
      padding: max(10px,env(safe-area-inset-top)) 14px max(28px,env(safe-area-inset-bottom));
    }
    .site-header{
      min-height:60px;padding:0 3px;gap:8px;
      background:rgba(7,9,35,.30);border-radius:0 0 14px 14px;
    }
    .brand-cloud{width:34px;height:34px}
    .brand-name{font-size:18px}
    .site-nav{gap:6px}
    .nav-link{min-height:34px;padding:6px 9px;font-size:11px}
    .nav-about{display:none}
    .hero-stage{
      display:block;min-height:0;padding:clamp(205px,58vw,340px) 0 22px;
    }
    .hero-content{max-width:none}
    .hero{margin-bottom:20px}
    .hero h1{font-size:clamp(40px,12vw,62px)}
    .hero-lead{font-size:clamp(17px,5vw,22px)!important;margin-top:12px!important}
    .hero h3{font-size:13px;margin-top:8px;max-width:34ch}
    .hero-visual-space{display:none}
    #panel-input{
      padding:15px 13px 14px;border-radius:17px;
      background:linear-gradient(135deg,rgba(225,220,255,.28),rgba(43,37,113,.48));
      backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
    }
    #panel-input .mode-switch{width:100%;display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}
    #panel-input .mode-btn{padding:9px 7px;font-size:12px}
    #singleInput{font-size:16px;min-height:46px}
    #batchInput{font-size:14px;min-height:190px}
    #panel-input .input-row{flex-direction:column;align-items:stretch}
    #panel-input #runBtn{width:100%;min-height:48px}
    #panel-input .hint{font-size:11px}
    .feature-grid{
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:9px;padding:0 0 24px;margin:0;
    }
    .feature-card{min-height:82px;padding:12px 10px;gap:9px;border-radius:14px}
    .feature-icon{width:40px;height:40px;font-size:22px}
    .feature-copy b{font-size:13px}
    .feature-copy small{font-size:10px}
    #panel-summary,#panel-results,.guide{padding:15px 13px}
    .panel-head{align-items:flex-start}
    .export-row{gap:6px}
    .export-row .btn-ghost{font-size:11px;padding:6px 8px}
    .site-footer{font-size:10px;gap:6px}
  }
  @media (max-width:380px){
    .wrap{padding-left:11px;padding-right:11px}
    .site-nav{gap:4px}
    .nav-link{padding:5px 7px}
    .hero-stage{padding-top:205px}
    .feature-card{padding:10px 8px;gap:7px}
    .feature-icon{width:35px;height:35px;font-size:19px}
    .feature-copy b{font-size:12px}
    .feature-copy small{font-size:9px}
  }
  @media (prefers-reduced-motion:reduce){
    html{scroll-behavior:auto}
    .nav-link{transition:none}
  }
</style>
</head>
<body>
<div class="toast-container" id="toastContainer" aria-live="polite"></div>
<div class="wrap">
  <header class="site-header">
    <a class="site-brand" href="#" aria-label="CFProxy-Web 首页">
      <span class="brand-cloud" aria-hidden="true">
        <svg viewBox="0 0 48 48" fill="none">
          <path d="M36.8 20.1h-2.7a12.3 12.3 0 1 0-11 17.8h13.7a8.9 8.9 0 0 0 0-17.8Z" stroke="currentColor" stroke-width="2.8" stroke-linecap="round"/>
          <path d="M24 33V17m-6 6 6-6 6 6" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </span>
      <span class="brand-name">CFProxy<span>-Web</span></span>
    </a>
    <nav class="site-nav" aria-label="主导航">
      <button class="nav-link nav-status" id="backendStatus" type="button" title="">
        <span class="dot live" id="backendDot"></span>
        <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><rect x="2" y="8" width="3" height="6" rx="1"/><rect x="6.5" y="5" width="3" height="9" rx="1"/><rect x="11" y="2" width="3" height="12" rx="1"/></svg>
        <span>状态</span>
      </button>
      <a class="nav-link nav-about" href="#about">关于</a>
    </nav>
  </header>
  <main class="hero-stage">
    <div class="hero-content">
      <header class="hero">
        <h1>CFProxy<span>-Web</span></h1>
        <p class="hero-lead">全球节点 · 极速上传 · 一键检测</p>
        <h3>让数据触达全球，连接更快的世界</h3>
      </header>
  <section class="panel" id="panel-input">
    <div class="mode-switch">
      <button class="mode-btn" data-mode="batch" type="button"><span aria-hidden="true">🌐</span>批量检测</button>
      <button class="mode-btn active" data-mode="single" type="button"><span aria-hidden="true">⚡</span>单个检测</button>
      <button class="mode-btn" data-mode="history" type="button"><span aria-hidden="true">🕐</span>历史记录</button>
    </div>
    <div class="input-row">
      <div class="input-area">
        <div id="input-single">
          <input id="singleInput" type="text" autocomplete="off" spellcheck="false"
            placeholder="单个 IP / 域名 / 网址，端口范围 1-65535，例如 1.1.1.1:443、proxy.example.com" />
        </div>
        <div id="input-batch" hidden>
          <textarea id="batchInput" spellcheck="false" wrap="off" autocomplete="off" autocapitalize="off" autocorrect="off" placeholder="随便粘贴，每行/每个都行，会自动识别其中的 IPv4、域名：&#10;1.1.1.1&#10;5.6.7.8:2053  这是一段说明文字也没关系&#10;[2606:4700::1111]&#10;proxy.example.com&#10;https://proxy.example.com:8443/&#10;（没写端口的一律按 443 处理，端口只支持 1-65535，超出范围会被自动忽略）&#10;&#10;也可以直接把 .txt / .csv 文件拖进来"></textarea>
          <div class="batch-tools">
            <span class="batch-count" id="batchCount">已识别 <b>0</b> 个目标</span>
            <div class="batch-btns">
              <button class="btn-ghost" id="importBtn" type="button">导入文件</button>
              <button class="btn-ghost" id="dedupeBtn" type="button">整理去重</button>
              <button class="btn-ghost" id="clearBtn" type="button">清空</button>
            </div>
          </div>
          <input type="file" id="fileInput" accept=".txt,.csv,.list,text/plain,text/csv" hidden />
        </div>
        <div id="panel-history" hidden>
          <div class="history-list" id="historyList"></div>
          <p class="hint" id="historyEmpty">暂无历史记录，检测过的目标会出现在这里</p>
        </div>
      </div>
      <button class="btn-primary" id="runBtn" type="button"><span aria-hidden="true">🚀</span>开始检测</button>
    </div>
    <p class="hint" id="inputHint">按 Enter 直接开始检测</p>
  </section>
    </div>
    <div class="hero-visual-space" aria-hidden="true"></div>
  </main>
  <section class="feature-grid" aria-label="产品优势">
    <article class="feature-card">
      <span class="feature-icon">ϟ</span>
      <span class="feature-copy"><b>极速响应</b><small>全球节点，毫秒级检测</small></span>
    </article>
    <article class="feature-card">
      <span class="feature-icon">✓</span>
      <span class="feature-copy"><b>精准可靠</b><small>多维度智能分析</small></span>
    </article>
    <article class="feature-card">
      <span class="feature-icon">☁</span>
      <span class="feature-copy"><b>简单易用</b><small>一键操作，轻松上手</small></span>
    </article>
    <article class="feature-card">
      <span class="feature-icon">◎</span>
      <span class="feature-copy"><b>全球覆盖</b><small>支持多地区节点</small></span>
    </article>
  </section>
  <section class="panel" id="panel-summary" hidden>
    <div class="panel-head">
      <h2>概览</h2>
      <span class="status-pill" id="statusPill">等待开始</span>
    </div>
    <div class="stat-grid">
      <div class="stat"><span class="stat-num" id="statTotal">0</span><span class="stat-label">目标数</span></div>
      <div class="stat good"><span class="stat-num" id="statValid">0</span><span class="stat-label">有效</span></div>
      <div class="stat pending"><span class="stat-num" id="statPending">0</span><span class="stat-label">待完成</span></div>
      <div class="stat bad"><span class="stat-num" id="statFail">0</span><span class="stat-label">失败</span></div>
    </div>
  </section>
  <section class="panel" id="panel-results" hidden>
    <div class="panel-head">
      <h2>检测结果</h2>
      <div class="export-row">
        <button class="btn-ghost" id="copyBtn" type="button">复制有效结果</button>
        <button class="btn-ghost" id="copyFailBtn" type="button">复制失败结果</button>
        <button class="btn-ghost" id="copyFilterBtn" type="button">复制筛选结果</button>
        <button class="btn-ghost" id="txtBtn" type="button">导出 TXT</button>
        <button class="btn-ghost" id="csvBtn" type="button">导出 CSV</button>
      </div>
    </div>
    <div class="filter-box" id="filterBox" hidden>
      <div class="filter-summary">筛选：<b id="filterSummary">全部结果</b></div>
      <div class="filter-row">
        <span class="filter-label">筛选</span>
        <div class="filter-chips" id="statusChips"></div>
      </div>
      <div class="filter-row">
        <span class="filter-label">地区</span>
        <div class="filter-chips" id="regionChips"></div>
      </div>
    </div>
    <div class="results-list" id="resultsList"></div>
  </section>
  <section class="panel guide" id="about">
    <h2>什么是 ProxyIP</h2>
    <div class="guide-grid">
      <div class="guide-item">
        <h3>它转发，而不是拥有</h3>
        <p>ProxyIP 不是 Cloudflare 分配给你的接入地址，而是一台第三方服务器 —— 它把自己端口收到的流量，反向代理到 Cloudflare 的边缘网络。</p>
      </div>
      <div class="guide-item">
        <h3>为什么 Workers 用得上它</h3>
        <p>Cloudflare Workers 发起的出站 TCP 连接无法直接到达 Cloudflare 自己的 IP 段。借一台第三方节点中转一次，就能绕开这层限制，间接触达 Cloudflare 服务。</p>
      </div>
      <div class="guide-item">
        <h3>怎样才算“有效”</h3>
        <p>这里不是单纯探测端口通不通，而是真的完成一次 TLS 握手、发出一次请求，确认目标稳定可用，并且愿意把流量代理到 Cloudflare。</p>
      </div>
    </div>
  </section>
  <footer class="site-footer">
    <span>OTC 自部署 ProxyIP 检测工具 TG频道@otcfxq</span>
    <span id="footerTime"></span>
  </footer>
</div>
<script>
(function () {
  "use strict";
  var HISTORY_KEY = "TG频道@otcfxq";
  var MAX_HISTORY = 8;
  var MAX_BATCH_TARGETS = 999;
  var mode = "single";
  var resultsData = [];
  var pendingCount = 0;
  var totalTargets = 0;
  var el = {
    backendStatus: document.getElementById("backendStatus"),
    backendDot: document.getElementById("backendDot"),
    modeBtns: document.querySelectorAll(".mode-btn"),
    singleWrap: document.getElementById("input-single"),
    batchWrap: document.getElementById("input-batch"),
    singleInput: document.getElementById("singleInput"),
    batchInput: document.getElementById("batchInput"),
    batchCount: document.getElementById("batchCount"),
    importBtn: document.getElementById("importBtn"),
    dedupeBtn: document.getElementById("dedupeBtn"),
    clearBtn: document.getElementById("clearBtn"),
    fileInput: document.getElementById("fileInput"),
    historyWrap: document.getElementById("panel-history"),
    historyList: document.getElementById("historyList"),
    historyEmpty: document.getElementById("historyEmpty"),
    inputHint: document.getElementById("inputHint"),
    runBtn: document.getElementById("runBtn"),
    panelSummary: document.getElementById("panel-summary"),
    panelResults: document.getElementById("panel-results"),
    statusPill: document.getElementById("statusPill"),
    statTotal: document.getElementById("statTotal"),
    statValid: document.getElementById("statValid"),
    statPending: document.getElementById("statPending"),
    statFail: document.getElementById("statFail"),
    resultsList: document.getElementById("resultsList"),
    copyBtn: document.getElementById("copyBtn"),
    copyFailBtn: document.getElementById("copyFailBtn"),
    copyFilterBtn: document.getElementById("copyFilterBtn"),
    txtBtn: document.getElementById("txtBtn"),
    csvBtn: document.getElementById("csvBtn"),
    footerTime: document.getElementById("footerTime"),
    filterBox: document.getElementById("filterBox"),
    filterSummary: document.getElementById("filterSummary"),
    statusChips: document.getElementById("statusChips"),
    regionChips: document.getElementById("regionChips"),
    toastContainer: document.getElementById("toastContainer")
  };
  var TOAST_DURATION_MS = 2200;
  function showToast(message, type) {
    if (!el.toastContainer) return;
    var toast = document.createElement("div");
    toast.className = "toast " + (type === "error" ? "error" : "success");
    var icon = document.createElement("span");
    icon.className = "toast-icon";
    icon.textContent = type === "error" ? "✕" : "✓";
    var text = document.createElement("span");
    text.textContent = message;
    toast.appendChild(icon);
    toast.appendChild(text);
    el.toastContainer.appendChild(toast);
    requestAnimationFrame(function () { toast.classList.add("show"); });
    setTimeout(function () {
      toast.classList.remove("show");
      setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 220);
    }, TOAST_DURATION_MS);
  }
  function writeTextToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      if (fallbackCopy(text)) resolve();
      else reject(new Error("execCommand copy failed"));
    });
  }
  function loadHistory() {
    try {
      var raw = localStorage.getItem(HISTORY_KEY);
      var list = raw ? JSON.parse(raw) : [];
      return Array.isArray(list) ? list : [];
    } catch (e) {
      return [];
    }
  }
  function saveHistory(value) {
    var list = loadHistory().filter(function (v) { return v !== value; });
    list.unshift(value);
    if (list.length > MAX_HISTORY) list = list.slice(0, MAX_HISTORY);
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch (e) {}
    renderHistoryList();
  }
  function renderHistoryList() {
    if (!el.historyList) return;
    var list = loadHistory();
    el.historyList.innerHTML = "";
    el.historyEmpty.hidden = list.length > 0;
    list.forEach(function (v, idx) {
      var item = document.createElement("button");
      item.type = "button";
      item.className = "history-item";
      var num = document.createElement("i");
      num.textContent = String(idx + 1);
      var label = document.createElement("span");
      label.textContent = v;
      item.appendChild(num);
      item.appendChild(label);
      item.addEventListener("click", function () {
        el.singleInput.value = v;
        setMode("single");
      });
      el.historyList.appendChild(item);
    });
  }
  renderHistoryList();
  var backendStatusLabel = "正在检测后端节点…";
  function setSummaryBackendStatus(state, text, tooltip) {
    var cls = state === "ok" ? "live" : state === "warn" ? "warn" : state === "error" ? "error" : "live";
    el.backendDot.className = "dot " + cls;
    backendStatusLabel = text;
    el.backendStatus.title = (text ? text + "。" : "") + (tooltip || "");
  }
  var BACKEND_STATUS_TIMEOUT_MS = 6000;
  function initBackendStatus() {
    setSummaryBackendStatus("warn", "正在检测后端节点…", "");
    var ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
    var timedOut = false;
    var timer = setTimeout(function () {
      timedOut = true;
      if (ctrl) { try { ctrl.abort(); } catch (e) {} }
    }, BACKEND_STATUS_TIMEOUT_MS);
    function getJson(url) {
      return fetch(url, {
        headers: { "Accept": "application/json" },
        signal: ctrl ? ctrl.signal : undefined
      })
        .then(function (res) {
          if (!res.ok) throw new Error("HTTP " + res.status);
          return res.json();
        });
    }
    function render(data) {
      clearTimeout(timer);
      var colo = data && data.colo ? String(data.colo).toUpperCase() : "";
      var country = data && data.country ? String(data.country).toUpperCase() : "";
      var city = data && data.city ? data.city : "";
      var label = [country, colo || city].filter(function (x) { return x; }).join(" · ");
      setSummaryBackendStatus(
        "ok",
        (label ? label + " " : "") + "服务已就绪",
        "检测结果基于本系统 所在节点发起 TLS 探测，若目标服务器与该节点距离较远，可能因网络延迟被误判为无效"
      );
    }
    function fail(err) {
      clearTimeout(timer);
      if (typeof console !== "undefined" && console.warn) {
        console.warn(
          "[backend-status] 后端节点定位失败：",
          timedOut ? "请求超时（" + BACKEND_STATUS_TIMEOUT_MS + "ms 无响应）" : err
        );
      }
      setSummaryBackendStatus(
        "error",
        timedOut ? "后端节点无响应" : "后端节点状态未知",
        timedOut
          ? "请求 ?backend=1 / ?echo=1 超过 " + (BACKEND_STATUS_TIMEOUT_MS / 1000) + " 秒未返回，请检查该路径的路由是否可达（可打开浏览器控制台查看详情）"
          : "无法获取当前节点信息，但检测功能通常仍可正常使用（详情见浏览器控制台）"
      );
    }
    getJson("?backend=1")
      .then(function (data) {
        if (data && data.colo) return render(data);
        return getJson("?echo=1").then(render);
      }, function () {
        return getJson("?echo=1").then(render);
      })
      .catch(fail);
  }
  initBackendStatus();
  el.backendStatus.addEventListener("click", function () {
    showToast(backendStatusLabel || "正在检测后端节点…");
  });
  function setMode(next) {
    mode = next;
    el.modeBtns.forEach(function (b) {
      var active = b.getAttribute("data-mode") === next;
      b.classList.toggle("active", active);
    });
    el.singleWrap.hidden = next !== "single";
    el.batchWrap.hidden = next !== "batch";
    el.historyWrap.hidden = next !== "history";
    el.runBtn.hidden = next === "history";
    el.singleInput.classList.remove("input-error");
    el.inputHint.classList.remove("error");
    if (next === "history") {
      renderHistoryList();
      el.inputHint.textContent = "点击一条历史记录填入单个检测";
      return;
    }
    el.inputHint.textContent = next === "single"
      ? "单目标仅支持一个 IP:端口（端口 1-65535），按 Enter 直接开始检测"
      : "自动识别粘贴内容里的 IPv4/IPv6/域名，未写端口默认 443，端口仅支持 1-65535（超出范围将被忽略），Ctrl/⌘ + Enter 开始";
    if (next === "batch") {
      updateBatchCount();
      el.batchInput.focus();
    } else {
      el.singleInput.focus();
    }
  }
  el.modeBtns.forEach(function (b) {
    b.addEventListener("click", function () { setMode(b.getAttribute("data-mode")); });
  });
  el.singleInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); startCheck(); }
  });
  el.runBtn.addEventListener("click", startCheck);
  function isValidIPv4(ip) {
    var p = ip.split(".");
    return p.length === 4 && p.every(function (x) {
      return /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255;
    });
  }
  function isValidPort(p) {
    if (p === null || p === undefined || p === "") return true;
    if (!/^\d{1,5}$/.test(String(p))) return false;
    var n = Number(p);
    return Number.isInteger(n) && n >= 1 && n <= 65535;
  }
  var DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
  var DEFAULT_PORT = "443";
  function extractTargets(rawText) {
    var work = " " + rawText + " ";
    var posMap = {};
    var order = [];
    function spaces(n) { return new Array(Math.max(n, 0) + 1).join(" "); }
    function add(hostForKey, port, pos) {
      if (!isValidPort(port)) return;
      var key = hostForKey;
      if (port || !DOMAIN_RE.test(hostForKey)) {
        key = hostForKey + ":" + (port || DEFAULT_PORT);
      }
      if (!Object.prototype.hasOwnProperty.call(posMap, key)) {
        posMap[key] = pos;
        order.push(key);
      } else if (pos < posMap[key]) {
        posMap[key] = pos;
      }
    }
    work = work.replace(/\[([^\]\[]*)\]\(([^)\s]*)\)/g, function (m, a, b) {
      return " " + a + "  " + b + " ";
    });
    work = work.replace(/\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^\s\/?#"'<>()]*)/g, function (m, auth) {
      var at = auth.lastIndexOf("@");
      if (at > -1) auth = auth.slice(at + 1);
      return spaces(m.length - auth.length) + auth;
    });
    work = work.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b/g, function (m, ip, port, offset) {
      if (isValidIPv4(ip)) { add(ip, port, offset); return spaces(m.length); }
      return m;
    });
    var tokRe = /[^\s,;，；()\[\]<>"']+/g;
    var mt;
    while ((mt = tokRe.exec(work)) !== null) {
      var t = mt[0].trim().split(/[\/?#]/)[0].replace(/[.。]+$/, "");
      if (!t) continue;
      var host = t, port = null;
      var idx = t.lastIndexOf(":");
      if (idx > -1 && /^\d{1,5}$/.test(t.slice(idx + 1))) {
        host = t.slice(0, idx);
        port = t.slice(idx + 1);
      }
      if (DOMAIN_RE.test(host)) add(host.toLowerCase(), port, mt.index);
    }
    return order.slice().sort(function (a, b) { return posMap[a] - posMap[b]; });
  }
  function parseSingleFallback(addr) {
    var host = addr, port = null;
    if (addr.charCodeAt(0) === 91) {
      var closeIdx = addr.indexOf("]");
      if (closeIdx !== -1) {
        host = addr.substring(1, closeIdx);
        var rest = addr.substring(closeIdx + 1);
        if (rest.indexOf(":") === 0) port = rest.substring(1);
      }
    } else {
      var colonCount = (addr.match(/:/g) || []).length;
      if (colonCount > 1) {
        host = addr;
      } else if (colonCount === 1) {
        var idx = addr.lastIndexOf(":");
        host = addr.substring(0, idx);
        port = addr.substring(idx + 1);
      }
    }
    return { host: host.trim(), port: port };
  }
  function getTargets() {
    var raw = mode === "single" ? el.singleInput.value : el.batchInput.value;
    if (mode === "batch") return extractTargets(raw);
    var single = raw.trim();
    if (!single) return [];
    var extracted = extractTargets(single);
    if (extracted.length) return extracted.slice(0, 1);
    var fb = parseSingleFallback(single);
    if (!fb.host || !isValidPort(fb.port)) return [];
    return [single];
  }
  function updateBatchCount() {
    var n = extractTargets(el.batchInput.value).length;
    var html = "已识别 <b>" + n + "</b> 个目标";
    if (n > MAX_BATCH_TARGETS) {
      html += ' <span class="warn">（超过 ' + MAX_BATCH_TARGETS + ' 个，仅检测前 ' + MAX_BATCH_TARGETS + ' 个）</span>';
    }
    el.batchCount.innerHTML = html;
  }
  el.batchInput.addEventListener("input", updateBatchCount);
  function dedupeBatchInput() {
    var list = extractTargets(el.batchInput.value);
    if (list.length === 0) {
      updateBatchCount();
      return;
    }
    el.batchInput.value = list.join("\n");
    updateBatchCount();
  }
  el.batchInput.addEventListener("paste", function () {
    setTimeout(dedupeBatchInput, 0);
  });
  el.batchInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      startCheck();
    }
  });
  el.clearBtn.addEventListener("click", function () {
    el.batchInput.value = "";
    updateBatchCount();
    el.batchInput.focus();
  });
  el.dedupeBtn.addEventListener("click", dedupeBatchInput);
  function readFileIntoBatch(file) {
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var text = String(reader.result || "");
      var cur = el.batchInput.value;
      el.batchInput.value = cur && !/\n$/.test(cur) ? cur + "\n" + text : cur + text;
      dedupeBatchInput();
    };
    reader.readAsText(file);
  }
  el.importBtn.addEventListener("click", function () { el.fileInput.click(); });
  el.fileInput.addEventListener("change", function () {
    var files = el.fileInput.files;
    for (var i = 0; i < files.length; i++) readFileIntoBatch(files[i]);
    el.fileInput.value = "";
  });
  ["dragenter", "dragover"].forEach(function (ev) {
    el.batchInput.addEventListener(ev, function (e) {
      e.preventDefault();
      el.batchInput.classList.add("drag-over");
    });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    el.batchInput.addEventListener(ev, function () {
      el.batchInput.classList.remove("drag-over");
    });
  });
  el.batchInput.addEventListener("drop", function (e) {
    e.preventDefault();
    var files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) {
      for (var i = 0; i < files.length; i++) readFileIntoBatch(files[i]);
    } else if (e.dataTransfer) {
      var txt = e.dataTransfer.getData("text");
      if (txt) {
        el.batchInput.value += (el.batchInput.value ? "\n" : "") + txt;
        dedupeBatchInput();
      }
    }
  });
  var filterStatus = "all";
  var filterRegion = "all";
  var STATUS_DEFS = [
    ["all", "全部"],
    ["valid", "有效"],
    ["fail", "失败"],
    ["v4", "OnlyIPv4"],
    ["v6", "OnlyIPv6"],
    ["both", "IPv4&IPv6"]
  ];
  function entryFamily(e) {
    if (e["有效ProxyIP"] !== true) return "";
    var t = e["出口类型"];
    return t === "ipv4" ? "4" : (t === "ipv6" ? "6" : "");
  }
  function groupKey(e) { return e["输入"] || e["目标"] || ""; }
  function buildGroupMap() {
    var map = {};
    resultsData.forEach(function (e) {
      if (entryFamily(e) === "") return;
      var k = groupKey(e);
      (map[k] = map[k] || []).push(e);
    });
    return map;
  }
  function dualPair(e, map) {
    var g = map[groupKey(e)];
    if (!g || g.length !== 2) return false;
    return entryFamily(g[0]) !== entryFamily(g[1]);
  }
  function entryGroup(e, map) {
    var fam = entryFamily(e);
    if (!fam) return "";
    if (e["双栈"] === true) return "both";
    if (dualPair(e, map)) return "both";
    return fam === "4" ? "v4" : "v6";
  }
  function matchStatus(e, s, map) {
    if (s === "all") return true;
    if (s === "valid") return e["有效ProxyIP"] === true;
    if (s === "fail") return e["有效ProxyIP"] !== true;
    return entryGroup(e, map) === s;
  }
  function makeChip(label, count, active, onClick) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "filter-chip" + (active ? " active" : "");
    b.textContent = label + "(" + count + ")";
    if (count === 0 && !active) b.disabled = true;
    b.addEventListener("click", onClick);
    return b;
  }
  function refreshFilters() {
    if (resultsData.length === 0) {
      el.filterBox.hidden = true;
      return;
    }
    el.filterBox.hidden = false;
    var map = buildGroupMap();
    el.statusChips.innerHTML = "";
    STATUS_DEFS.forEach(function (d) {
      var n = resultsData.filter(function (e) { return matchStatus(e, d[0], map); }).length;
      el.statusChips.appendChild(makeChip(d[1], n, filterStatus === d[0], function () {
        filterStatus = d[0];
        refreshFilters();
      }));
    });
    var counts = {};
    resultsData.forEach(function (e) {
      var c = e["出口国家"] || e["国家"];
      if (c && e["有效ProxyIP"] === true) counts[c] = (counts[c] || 0) + 1;
    });
    var codes = Object.keys(counts).sort(function (a, b) {
      return counts[b] - counts[a] || (a < b ? -1 : 1);
    });
    el.regionChips.innerHTML = "";
    el.regionChips.appendChild(makeChip("全部", resultsData.length, filterRegion === "all", function () {
      filterRegion = "all";
      refreshFilters();
    }));
    codes.forEach(function (c) {
      el.regionChips.appendChild(makeChip(c, counts[c], filterRegion === c, function () {
        filterRegion = c;
        refreshFilters();
      }));
    });
    var kids = el.resultsList.children;
    var shown = 0;
    for (var i = 0; i < kids.length; i++) {
      var card = kids[i];
      var e = card._entry;
      if (!e) {
        card.hidden = !(filterStatus === "all" && filterRegion === "all");
        continue;
      }
      var show = matchStatus(e, filterStatus, map) &&
        (filterRegion === "all" || (e["出口国家"] || e["国家"]) === filterRegion);
      card.hidden = !show;
      if (show) shown++;
    }
    var parts = [];
    STATUS_DEFS.forEach(function (d) { if (d[0] === filterStatus && d[0] !== "all") parts.push(d[1]); });
    if (filterRegion !== "all") parts.push(filterRegion);
    el.filterSummary.textContent = (parts.length ? parts.join(" · ") : "全部结果") + "（显示 " + shown + " 条）";
  }
  function resetPanels(targets) {
    resultsData = [];
    totalTargets = targets.length;
    pendingCount = targets.length;
    el.panelSummary.hidden = false;
    el.panelResults.hidden = false;
    el.statTotal.textContent = String(totalTargets);
    el.statValid.textContent = "0";
    el.statFail.textContent = "0";
    el.statPending.textContent = String(pendingCount);
    el.statusPill.textContent = "检测中";
    el.statusPill.className = "status-pill running";
    el.resultsList.innerHTML = "";
    filterStatus = "all";
    filterRegion = "all";
    refreshFilters();
    targets.forEach(function (t, idx) { makePlaceholderCard(t, idx, true); });
  }
  function buildPlaceholder(label, subText) {
    var card = document.createElement("div");
    card.className = "result-card loading";
    var head = document.createElement("div");
    head.className = "rc-head";
    var left = document.createElement("div");
    var t = document.createElement("div");
    t.className = "rc-target";
    t.textContent = label;
    var sub = document.createElement("div");
    sub.className = "rc-sub";
    sub.textContent = subText;
    left.appendChild(t);
    left.appendChild(sub);
    var badge = document.createElement("span");
    badge.className = "badge loading";
    var spinner = document.createElement("span");
    spinner.className = "spinner";
    badge.appendChild(spinner);
    head.appendChild(left);
    head.appendChild(badge);
    card.appendChild(head);
    card._title = t;
    card._sub = sub;
    return card;
  }
  function makePlaceholderCard(target, idx, queued) {
    var card = buildPlaceholder(target, queued ? "排队中…" : "正在解析…");
    card.id = "rc-" + idx;
    el.resultsList.appendChild(card);
    return card;
  }
  function setCardSub(card, text) {
    if (card && card._sub) card._sub.textContent = text;
  }
  function asnText(e) {
    var asn = e["ASN"] ? "AS" + e["ASN"] : "";
    var org = e["组织"] || "";
    if (asn && org) return asn + " · " + org;
    return asn || org || "—";
  }
  function exitInfo(e) {
    var own = { ip: e["出口ip"] || "—", type: e["出口类型"] || "—" };
    if (e["双栈"] === true) return { ip: e["出口IPv4"] + " / " + e["出口IPv6"], type: "双栈" };
    if (e["有效ProxyIP"] !== true) return own;
    var map = buildGroupMap();
    if (!dualPair(e, map)) return own;
    var v4 = "", v6 = "";
    map[groupKey(e)].forEach(function (x) {
      if (entryFamily(x) === "4") v4 = x["出口ip"]; else v6 = x["出口ip"];
    });
    return { ip: v4 + " / " + v6, type: "双栈" };
  }
  function normalizeColoCode(colo) {
    if (!colo || typeof colo !== "string") return null;
    var c = colo.trim().toUpperCase();
    return /^[A-Z]{3}$/.test(c) ? c : null;
  }
  function getLatencyTooltipText(data) {
    var coloCode = normalizeColoCode(data && data.colo);
    var coloText = coloCode ? "Cloudflare " + coloCode + " 机房" : "Cloudflare 测试机房";
    return "这个延迟不是你到 ProxyIP 的检测延迟，而是 " + coloText + " 到 ProxyIP 的检测延迟。";
  }
  function fallbackCopy(text) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      return true;
    } catch (e) {
      return false;
    }
  }
  function flashCopied(el) {
    el.classList.add("copied");
    clearTimeout(el._copyTimer);
    el._copyTimer = setTimeout(function () {
      el.classList.remove("copied");
    }, 900);
  }
  function copyText(text, feedbackEl, toastLabel) {
    if (!text) return;
    writeTextToClipboard(text)
      .then(function () {
        if (feedbackEl) flashCopied(feedbackEl);
        showToast("已复制" + (toastLabel ? "：" + toastLabel : ""), "success");
      })
      .catch(function (err) {
        console.error("复制失败", err);
        showToast("复制失败，请检查浏览器权限", "error");
      });
  }
  function refillGroup(key) {
    var kids = el.resultsList.children;
    for (var i = 0; i < kids.length; i++) {
      var c = kids[i];
      if (c._entry && c._entry["输入"] === key && c._entry["有效ProxyIP"] === true) fillCard(c, c._entry);
    }
  }
  function fieldRow(container, label, value, tooltip, copyable) {
    var wrap = document.createElement("div");
    wrap.className = "rc-field";
    var l = document.createElement("div");
    l.className = "rc-field-label" + (tooltip ? " has-tip" : "");
    l.textContent = label;
    if (tooltip) {
      l.title = tooltip;
      wrap.title = tooltip;
    }
    var v = document.createElement("div");
    v.className = "rc-field-value";
    v.textContent = value;
    if (copyable && value && value !== "—") {
      v.className += " copyable";
      v.title = "点击复制";
      v.addEventListener("click", function () {
        copyText(value, v, value);
      });
    }
    wrap.appendChild(l);
    wrap.appendChild(v);
    container.appendChild(wrap);
  }
  function fillCard(card, entry) {
    card.innerHTML = "";
    var ok = entry["有效ProxyIP"] === true;
    card.className = "result-card " + (ok ? "ok" : "fail");
    card._entry = entry;
    var head = document.createElement("div");
    head.className = "rc-head";
    var left = document.createElement("div");
    var t = document.createElement("div");
    t.className = "rc-target copyable";
    t.textContent = entry["目标"] || "";
    t.title = "点击复制";
    t.addEventListener("click", function () {
      var copyValue = ok
        ? hostPort(entry)
        : (entry["目标"] || "");
      copyText(copyValue, t, copyValue);
    });
    left.appendChild(t);
    if (entry["解析地址族"]) {
      var sub = document.createElement("div");
      sub.className = "rc-sub";
      sub.textContent = "解析地址族: " + entry["解析地址族"] + (entry["解析来源"] ? " · " + entry["解析来源"] + " 记录" : "");
      left.appendChild(sub);
    }
    var badge = document.createElement("span");
    badge.className = "badge " + (ok ? "ok" : "fail");
    badge.textContent = ok ? "✓ 有效" : "✕ 无效";
    head.appendChild(left);
    head.appendChild(badge);
    card.appendChild(head);
    if (ok) {
      var fields = document.createElement("div");
      fields.className = "rc-fields";
      var countryRegion = [entry["出口国家"], entry["出口地区"]]
        .filter(function (v) { return v && v !== "未知"; })
        .join(" / ") || "—";
      fieldRow(fields, "数据中心", entry["数据中心"] || "—");
      fieldRow(fields, "国家 / 地区", countryRegion);
      fieldRow(fields, "城市", entry["出口城市"] || "—");
      fieldRow(fields, "响应时间", entry["响应时间"] || "—", getLatencyTooltipText({ colo: entry["数据中心"] }));
      var ex = exitInfo(entry);
      fieldRow(fields, "出口 IP", ex.ip, null, true);
      fieldRow(fields, "出口类型", ex.type);
      fieldRow(fields, "ASN", asnText(entry));
      fieldRow(fields, "Cloudflare 官方 IP", entry["是否为Cloudflare官方IP"] ? "是" : "否");
      card.appendChild(fields);
    } else {
      var reason = document.createElement("div");
      reason.className = "rc-reason";
      reason.textContent = entry["失败原因"] || "未知错误";
      card.appendChild(reason);
    }
  }
  function updateStats() {
    var valid = 0, fail = 0;
    resultsData.forEach(function (e) {
      if (e["有效ProxyIP"] === true) valid++; else fail++;
    });
    el.statValid.textContent = String(valid);
    el.statFail.textContent = String(fail);
    el.statPending.textContent = String(pendingCount);
    refreshFilters();
    if (pendingCount <= 0) {
      el.statusPill.textContent = "✓ 已完成";
      el.statusPill.className = "status-pill done";
      el.runBtn.disabled = false;
    }
  }
  var BATCH_CONCURRENCY = 8;
  var BATCH_STAGGER_MS = 120;
  var taskQueue = [];
  var activeTasks = 0;
  var gate = false;
  function pump() {
    if (gate) return;
    while (!gate && activeTasks < BATCH_CONCURRENCY && taskQueue.length) {
      var task = taskQueue.shift();
      activeTasks++;
      gate = true;
      var done = function () { activeTasks--; pump(); };
      Promise.resolve().then(task).then(done, done);
      setTimeout(function () { gate = false; pump(); }, BATCH_STAGGER_MS);
    }
  }
  function schedule(task) {
    taskQueue.push(task);
    pump();
  }
  function finishOne() {
    pendingCount--;
    updateStats();
  }
  function addEntry(card, entry) {
    fillCard(card, entry);
    resultsData.push(entry);
  }
  function jsonHeaders() { return { "Accept": "application/json" }; }
  var PROBE_BATCH_SIZE = 10;
  var PROBE_BATCH_WAIT_MS = 150;
  var probeJobQueue = [];
  var probeFlushTimer = null;
  function parsePlainIpTarget(target) {
    var fb = parseSingleFallback(target);
    if (!fb.host) return null;
    var port = String(fb.port || "443").trim();
    if (!isValidPort(port)) return null;
    if (!isValidIPv4(fb.host)) return null;
    var family = "ipv4";
    var addr = fb.host + ":" + port;
    return { host: fb.host, port: Number(port), family: family, addr: addr };
  }
  function enqueueProbeJob(job, card) {
    probeJobQueue.push({ job: job, card: card });
    if (probeJobQueue.length >= PROBE_BATCH_SIZE) {
      flushProbeJobs();
    } else if (!probeFlushTimer) {
      probeFlushTimer = setTimeout(function () {
        probeFlushTimer = null;
        flushProbeJobs();
      }, PROBE_BATCH_WAIT_MS);
    }
  }
  function dispatchProbeBatch(batch) {
    var directJobs = batch.filter(function (x) { return x.job.sni || x.job.viaHostname; });
    var batchJobs = batch.filter(function (x) { return !x.job.sni && !x.job.viaHostname; });
    if (batchJobs.length) schedule(function () { return probeBatch(batchJobs); });
    directJobs.forEach(function (x) { schedule(function () { return probeJob(x.job, x.card); }); });
  }
  function flushProbeJobs() {
    if (probeFlushTimer) { clearTimeout(probeFlushTimer); probeFlushTimer = null; }
    while (probeJobQueue.length) {
      dispatchProbeBatch(probeJobQueue.splice(0, PROBE_BATCH_SIZE));
    }
  }
  function finishProbeJob(job, card, entry) {
    if (!entry || typeof entry !== "object") entry = { "有效ProxyIP": false, "失败原因": "无返回结果" };
    entry["目标"] = job.label;
    if (job.isDomain) {
      entry["输入"] = job.input;
      entry["解析地址族"] = String(job.family || "").toUpperCase();
      if (job.source) entry["解析来源"] = job.source;
    }
    if (job.viaHostname && entry["有效ProxyIP"] !== true && entry["失败原因"] &&
        entry["失败原因"].indexOf("DoH 未解析到") !== 0) {
      entry["失败原因"] = "DoH 未解析到 A/TXT 记录，直连域名探测也失败：" + entry["失败原因"];
    }
    addEntry(card, entry);
    if (job.isDomain) {
      var validCount = 0;
      resultsData.forEach(function (e) {
        if (e["输入"] === job.input && e["有效ProxyIP"] === true) validCount++;
      });
      if (validCount === 2) refillGroup(job.input);
    }
    finishOne();
  }
  function probeBatch(items) {
    items.forEach(function (x) { setCardSub(x.card, "正在检测中…"); });
    var api = location.pathname + "?ip=" + encodeURIComponent(items.map(function (x) { return x.job.addr; }).join(","));
    return fetch(api, { headers: jsonHeaders() })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        var arr = Array.isArray(data) ? data : [];
        items.forEach(function (x, i) {
          var entry = arr[i];
          if (data && !Array.isArray(data) && data.error) entry = { "有效ProxyIP": false, "失败原因": String(data.error) };
          finishProbeJob(x.job, x.card, entry);
        });
      })
      .catch(function (err) {
        items.forEach(function (x) {
          finishProbeJob(x.job, x.card, { "有效ProxyIP": false, "失败原因": "请求失败: " + (err && err.message ? err.message : String(err)) });
        });
      });
  }
  function resolveInput(target, idx) {
    var card = document.getElementById("rc-" + idx);
    var plain = parsePlainIpTarget(target);
    if (plain) {
      setCardSub(card, "排队中…");
      enqueueProbeJob({
        host: plain.host,
        port: plain.port,
        addr: plain.addr,
        family: plain.family,
        isDomain: false,
        domain: "",
        source: "",
        viaHostname: false,
        input: target,
        sni: "",
        label: target
      }, card);
      return Promise.resolve();
    }
    setCardSub(card, "正在解析…");
    var api = location.pathname + "?ip=" + encodeURIComponent(target) + "&resolve=1";
    return fetch(api, { headers: jsonHeaders() })
      .then(function (res) { return res.json(); })
      .then(function (jobs) {
        if (!Array.isArray(jobs) || jobs.length === 0) throw new Error("没有可检测的目标");
        return jobs;
      })
      .then(function (jobs) {
        var extra = jobs.length - 1;
        totalTargets += extra;
        pendingCount += extra;
        el.statTotal.textContent = String(totalTargets);
        el.statPending.textContent = String(pendingCount);
        var prev = card;
        jobs.forEach(function (job, j) {
          var c = card;
          if (j === 0) {
            if (c._title) c._title.textContent = job.label;
            setCardSub(c, "排队中…");
          } else {
            c = buildPlaceholder(job.label, "排队中…");
            el.resultsList.insertBefore(c, prev.nextSibling);
          }
          prev = c;
          enqueueProbeJob(job, c);
        });
      }, function (err) {
        addEntry(card, {
          "目标": target,
          "有效ProxyIP": false,
          "失败原因": "解析失败: " + (err && err.message ? err.message : String(err))
        });
        finishOne();
      });
  }
  function probeJob(job, card) {
    setCardSub(card, "正在检测中…");
    var api = location.pathname + "?ip=" + encodeURIComponent(job.addr) + "&direct=1" +
      (job.sni ? "&sni=" + encodeURIComponent(job.sni) : "");
    return fetch(api, { headers: jsonHeaders() })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        var entry = Array.isArray(data) ? data[0] : data;
        if (data && !Array.isArray(data) && data.error) entry = { "有效ProxyIP": false, "失败原因": String(data.error) };
        if (!entry || typeof entry !== "object") entry = { "有效ProxyIP": false, "失败原因": "无返回结果" };
        return entry;
      })
      .catch(function (err) {
        return { "有效ProxyIP": false, "失败原因": "请求失败: " + (err && err.message ? err.message : String(err)) };
      })
      .then(function (entry) { finishProbeJob(job, card, entry); });
  }
  function startCheck() {
    if (mode === "history") return;
    var targets = getTargets();
    el.singleInput.classList.remove("input-error");
    el.inputHint.classList.remove("error");
    if (targets.length === 0) {
      if (mode === "single" && el.singleInput.value.trim()) {
        el.singleInput.classList.add("input-error");
        el.inputHint.classList.add("error");
        el.inputHint.textContent = "目标格式不正确，或端口不在 1-65535 范围内";
      } else {
        el.inputHint.textContent = "先输入至少一个目标";
      }
      return;
    }
    if (mode === "batch" && targets.length > MAX_BATCH_TARGETS) {
      targets = targets.slice(0, MAX_BATCH_TARGETS);
    }
    if (mode === "single") {
      saveHistory(targets[0]);
    }
    el.runBtn.disabled = true;
    resetPanels(targets);
    taskQueue = [];
    probeJobQueue = [];
    if (probeFlushTimer) { clearTimeout(probeFlushTimer); probeFlushTimer = null; }
    targets.forEach(function (t, idx) {
      schedule(function () { return resolveInput(t, idx); });
    });
  }
  function plainIp(e) {
    var ip = String(e["ip"] || "");
    if (ip.charAt(0) === "[" && ip.charAt(ip.length - 1) === "]") ip = ip.slice(1, -1);
    return ip;
  }
  function hostPort(e) {
    var ip = plainIp(e);
    if (ip.indexOf(":") !== -1) ip = "[" + ip + "]";
    return ip + ":" + (e["端口"] != null ? e["端口"] : "");
  }
  function formatLine(e) {
    var country = e["出口国家"] || e["国家"] || "";
    var region = e["出口地区"] || "";
    var city = e["出口城市"] || e["城市"] || "";
    var asn = e["ASN"] ? "AS" + e["ASN"] : "";
    var exitIp = e["双栈"] === true ? e["出口IPv4"] + "/" + e["出口IPv6"] : (e["出口ip"] || "");
    var exitType = e["双栈"] === true ? "双栈" : (e["出口类型"] || "");
    var tail = [country, region, city, asn, e["组织"] || "", exitIp, exitType]
      .filter(function (x) { return x; })
      .join(" ");
    return hostPort(e) + (tail ? "#" + tail : "");
  }
  function orderedEntries() {
    var out = [];
    var kids = el.resultsList.children;
    for (var i = 0; i < kids.length; i++) {
      if (kids[i]._entry) out.push(kids[i]._entry);
    }
    return out;
  }
  function validLines() {
    return orderedEntries()
      .filter(function (e) { return e["有效ProxyIP"] === true; })
      .map(formatLine);
  }
  function download(filename, content, mime) {
    var blob = new Blob([content], { type: mime });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  }
  el.copyBtn.addEventListener("click", function () {
    var lines = validLines();
    if (lines.length === 0) {
      showToast("暂无有效结果可复制", "error");
      return;
    }
    writeTextToClipboard(lines.join("\n"))
      .then(function () {
        var original = el.copyBtn.textContent;
        el.copyBtn.textContent = "已复制";
        setTimeout(function () { el.copyBtn.textContent = original; }, 1200);
        showToast("已复制 " + lines.length + " 条有效结果", "success");
      })
      .catch(function (err) {
        console.error("复制失败", err);
        showToast("复制失败，请检查浏览器权限", "error");
      });
  });
  function failedLines() {
    var seen = {};
    var out = [];
    orderedEntries().forEach(function (e) {
      if (e["有效ProxyIP"] === true) return;
      var v = String(e["目标"] || "").trim();
      var arrow = v.indexOf(" -> ");
      if (arrow !== -1) v = v.slice(arrow + 4).trim();
      if (!v || seen[v]) return;
      seen[v] = true;
      out.push(v);
    });
    return out;
  }
  el.copyFailBtn.addEventListener("click", function () {
    var lines = failedLines();
    if (lines.length === 0) {
      showToast("暂无失败结果可复制", "error");
      return;
    }
    writeTextToClipboard(lines.join("\n"))
      .then(function () {
        var original = el.copyFailBtn.textContent;
        el.copyFailBtn.textContent = "已复制";
        setTimeout(function () { el.copyFailBtn.textContent = original; }, 1200);
        showToast("已复制 " + lines.length + " 条失败结果", "success");
      })
      .catch(function (err) {
        console.error("复制失败", err);
        showToast("复制失败，请检查浏览器权限", "error");
      });
  });
  function filteredLines() {
    var out = [];
    var seen = {};
    var kids = el.resultsList.children;
    for (var i = 0; i < kids.length; i++) {
      var c = kids[i];
      var e = c._entry;
      if (!e || c.hidden) continue;
      if (e["有效ProxyIP"] === true) {
        out.push(formatLine(e));
      } else if (filterStatus === "fail") {
        var v = String(e["目标"] || "").trim();
        var arrow = v.indexOf(" -> ");
        if (arrow !== -1) v = v.slice(arrow + 4).trim();
        if (!v || seen[v]) continue;
        seen[v] = true;
        out.push(v);
      }
    }
    return out;
  }
  el.copyFilterBtn.addEventListener("click", function () {
    var lines = filteredLines();
    if (lines.length === 0) {
      showToast("当前筛选下暂无结果可复制", "error");
      return;
    }
    writeTextToClipboard(lines.join("\n"))
      .then(function () {
        var original = el.copyFilterBtn.textContent;
        el.copyFilterBtn.textContent = "已复制";
        setTimeout(function () { el.copyFilterBtn.textContent = original; }, 1200);
        showToast("已复制 " + lines.length + " 条筛选结果", "success");
      })
      .catch(function (err) {
        console.error("复制失败", err);
        showToast("复制失败，请检查浏览器权限", "error");
      });
  });
  el.txtBtn.addEventListener("click", function () {
    var lines = validLines();
    if (lines.length === 0) return;
    download("proxyip-valid.txt", lines.join("\n"), "text/plain;charset=utf-8");
  });
  el.csvBtn.addEventListener("click", function () {
    var valid = orderedEntries().filter(function (e) { return e["有效ProxyIP"] === true; });
    if (valid.length === 0) return;
    var header = ["节点", "ip", "端口", "出口国家", "出口地区", "出口地区代码", "出口城市", "ASN", "组织", "数据中心", "响应时间", "出口ip", "出口类型"];
    function cell(e, k) {
      if (k === "节点") return formatLine(e);
      if (k === "ip") return plainIp(e);
      if (k === "出口国家") return e["出口国家"] || e["国家"] || "";
      if (k === "出口地区") return e["出口地区"] || "";
      if (k === "出口地区代码") return e["出口地区代码"] || "";
      if (k === "出口城市") return e["出口城市"] || e["城市"] || "";
      var v = e[k];
      return v === undefined || v === null ? "" : String(v);
    }
    var rows = [header.join(",")];
    valid.forEach(function (e) {
      rows.push(header.map(function (k) {
        return '"' + cell(e, k).replace(/"/g, '""') + '"';
      }).join(","));
    });
    download("proxyip-valid.csv", "\uFEFF" + rows.join("\n"), "text/csv;charset=utf-8");
  });
  el.footerTime.textContent = new Date().getFullYear() + " · " + location.hostname;
})();
</script>
</body>
</html>
