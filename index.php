<?php

require_once 'classes/PHPSecurityInspector.php';

if (isset($_POST['submit']) && isset($_FILES['code-to-check'])) {
    $file = file_get_contents($_FILES['code-to-check']['tmp_name']);
    if (strpos($file, '<?php') !== false) {
        $code = $file;
    } else {
        $code = '<?php ' . $file;
    }


    $inspector = new PHPSecurityInspector($code, true);
} else {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>PHPSecurityInspector Demo</title>
    </head>
    <body>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="code-to-check" />
        <input type="submit" value="Submeter" name="submit" />
    </form>
    </body>
    </html>
<?php } ?>