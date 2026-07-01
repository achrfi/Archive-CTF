<?php
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

$s = new Sanitizer();
$danger = [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<script>alert(1)</script>',
    '<iframe srcdoc=<script>alert(1)</script>>',
    '<meta http-equiv=refresh content=0;url=javascript:alert(1)>',
    '<link rel=stylesheet href=javascript:alert(1)>',
];
$prefixes = ['', '<style>', '<style><a title=</style>', '<style><x title=</style>', '<style><p title=</style>', '<style><!--', '<textarea>', '<title>', '<x <'];
$suffixes = ['', '</style>', '></style>', '<x></style>', '</textarea>', '</title>', '<'];

foreach ($prefixes as $pre) {
    foreach ($danger as $d) {
        foreach ($suffixes as $suf) {
            $in = $pre . $d . $suf;
            $out = $s->purify($in);
            $lo = strtolower($out);
            if (strpos($lo, 'onerror') !== false || strpos($lo, 'onload') !== false || strpos($lo, '<script') !== false || strpos($lo, '<svg') !== false || strpos($lo, '<iframe') !== false || strpos($lo, '<meta') !== false || strpos($lo, '<link') !== false || strpos($lo, 'javascript:') !== false) {
                echo "IN: $in\nOUT: $out\n---\n";
            }
        }
    }
}
