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

$ip = callerIp('192.168.0.26');

if ($ip) {
    echo "I see you.";
}
?>
