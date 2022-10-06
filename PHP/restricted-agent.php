<?php
function callerAgent($caller) {
    $agent = $_SERVER['HTTP_USER_AGENT'];
    if ($caller === $agent) {
        return TRUE;
    } else {
        return FALSE;
    }
}

$agent = callerAgent('Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0');

if ($agent) {
    echo "I see you.";
}
?>
