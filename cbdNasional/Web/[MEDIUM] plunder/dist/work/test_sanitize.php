<?php
if ($argc < 2) {
    fwrite(STDERR, "usage: php work/test_sanitize.php '<html>'\n");
    exit(1);
}

$source = file_get_contents(__DIR__ . '/../src/html/index.php');
$source = substr($source, strpos($source, 'class Sanitizer'));
$classOnly = substr($source, 0, strpos($source, "\ntry {"));
eval($classOnly);

if (!function_exists('mb_strpos')) {
    function mb_strpos($haystack, $needle, $offset = 0, $encoding = null) {
        return strpos($haystack, $needle, $offset);
    }
    function mb_substr($string, $start, $length = null, $encoding = null) {
        return $length === null ? substr($string, $start) : substr($string, $start, $length);
    }
}

$sanitizer = new Sanitizer();
echo $sanitizer->purify($argv[1]);
