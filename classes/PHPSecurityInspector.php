<?php

require_once 'vendor/PhpParser/Autoloader.php';

PhpParser\Autoloader::register();

use PhpParser\Error;
use PhpParser\ParserFactory;

class PHPSecurityInspector {
    private $_parser;
    private $vulnerabilities = array(
      "SQL" => array("mysql_query","mysql_unbuffered_query","mysql_db_query",
            "mysqli_query","mysqli_real_query","mysqli_master_query",
            "mysqli_multi_query","mysqli_stmt_execute","mysqli_execute",
            "mysqli::query","mysqli::multi_query","mysqli::real_query",
            "mysqli_stmt::execute","db2_exec", "pg_query","pg_send_query"),
      "File" => array("fopen", "file_get_contents","file","copy","unlink",
            "move_uploaded_file","imagecreatefromgd2","imagecreatefromgd2part",
            "imagecreatefromgd", "imagecreatefromgif","imagecreatefromjpeg",
            "imagecreatefrompng","imagecreatefromstring","imagecreatefromwbmp",
            "imagecreatefromxbm","imagecreatefromxpm", "require","require_once",
            "include","include_once"),
      "Source" => array("readfile"),
      "Command" => array("passthru","system","shell_exec","exec","pcntl_exec","popen"),
      "XSS" => array("echo","print","printf","die","error","exit","file_put_contents",
			      "file_get_contents"),);

    /**
     * @param String    $code       Code to be inspected
     */
    public function __construct($code) {
        $this->_parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP5);

        try {
            $stmts = $this->_parser->parse($code);
            echo '<pre>';
            print_r($stmts);
            echo '</pre>';
        } catch (Error $e) {
            echo 'Parse Error: ', $e->getMessage();
        }
    }
}
