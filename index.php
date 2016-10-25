<?php

require_once 'vendor/PhpParser/Autoloader.php';

PhpParser\Autoloader::register();

use PhpParser\Error;
use PhpParser\ParserFactory;


$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP5);

$code = '<?php $nis=$_POST[\'nis\'];
$query="SELECT *FROM siswa WHERE nis=\'$nis\'";
$q=mysql_query($query,$koneksi); ?>';

try {
    $stmts = $parser->parse($code);
    echo 'All worked fine';
    echo '<pre>';
    print_r($stmts);
    echo '</pre>';
} catch (Error $e) {
    echo 'Parse Error: ', $e->getMessage();
}
