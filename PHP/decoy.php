<?php
function decoy() {
    $decoy = 'Li4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uDQouLi4uLi4uIyMuLi4uLiMjLi4uLi4jIy4uLi4uLi4uLi4uLi4NCi4uLi4uLi4uLiMjLi4uLi4jIy4uLi4uIyMuLi4uLi4uLi4uLg0KLi4uLi4uLiMjLi4uLi4jIy4uLi4jIy4uLi4uLi4uLi4uLi4uDQouLi4uLi4uIyMuLi4uLiMjLi4uLiMjLi4uLi4uLi4uLi4uLi4NCi4uLi4uLi4uLiMjLi4uLi4jIy4uLiMjLi4uLi4uLi4uLi4uLg0KLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uDQouLi4uLi4jIyMjIyMjIyMjIyMjIyMjIyMjIy4uLi4uLi4uLi4NCi4uLi4uLiMjLi4uLi4uLi4uLi4uLi4uLiMjIyMjIy4uLi4uLg0KLi4uLi4uIyMuLi5UcnkuSGFyZGVyLi4uIyMuLiMjLi4uLi4uDQouLi4uLi4jIy4uLi4uLi4uLi4uLi4uLi4jIy4uIyMuLi4uLi4NCi4uLi4uLiMjLi4uLi4uLi4uLi4uLi4uLiMjIyMjIy4uLi4uLg0KLi4uLi4uLi4jIy4uLi4uLi4uLi4uLiMjLi4uLi4uLi4uLi4uDQouLi4uIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjLi4uLi4uLi4NCi4uLi4jIy4uLi4uLi4uLi4uLi4uLi4uLi4uIyMuLi4uLi4uLg0KLi4uLi4uIyMjIyMjIyMjIyMjIyMjIyMjIyMuLi4uLi4uLi4uDQouLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4=';
    $agent = $_SERVER['HTTP_USER_AGENT'];
    if(preg_match('((?i)(curl|wget|powershell))', $agent) === 1) {
        echo base64_decode($decoy);
    } else {
        echo '<pre>' . base64_decode($decoy) . '</pre>';
    }
}
decoy();
?>
