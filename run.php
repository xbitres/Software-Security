<?php

require_once 'classes/PHPSecurityInspector.php';

if (!isset($argv[1])) {
    echo "No file selected.\n";
    exit();
}

echo "File to analysed: \t" . $argv[1] . "\n";

$filename = $argv[1];

if (!file_exists($filename)) {
    echo "The file you inserted does not exist.\n";
    exit();
}

$fid = fopen($filename, "r");

if (!$fid) {
    echo "You do not have permission to access the file.\n";
    exit();
}

$file = fread($fid, filesize($filename));

echo "File contents:\n$file\n";

if (strpos($file, '<?php') !== false) {
    $code = $file;
} else {
    $code = '<?php ' . $file;
}

$inspector = new PHPSecurityInspector($code);