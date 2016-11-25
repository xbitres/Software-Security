<?php

require_once 'classes/PHPSecurityInspector.php';

print_r($argv);

if (isset($_POST['submit']) && isset($_FILES['code-to-check'])) {
    $file = file_get_contents($_FILES['code-to-check']['tmp_name']);
    if (strpos($file, '<?php') !== false) {
        $code = $file;
    } else {
        $code = '<?php ' . $file;
    }


    $inspector = new PHPSecurityInspector($code);
}