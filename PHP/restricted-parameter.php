<?php
function callerParam($caller) {
    $param = isset($_GET[$caller]);
    if ($param) {
        return TRUE;
    } else {
        return FALSE;
    }
}

$param = callerParam('callback');

if ($param) {
    echo "I see you.";
}
?>
