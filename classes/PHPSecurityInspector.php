<?php

require_once 'vendor/PhpParser/Autoloader.php';

require_once 'Sink.php';

PhpParser\Autoloader::register();

use PhpParser\Error;
use PhpParser\ParserFactory;

class PHPSecurityInspector {
    private $_parser;
    private $vulnerabilities = array(
      "SQL" => array(
        //
        "mysql_query" => array("mysql_escape_string", "mysql_real_escape_string"),
        "mysql_unbuffered_query" => array("mysql_escape_string", "mysql_real_escape_string"),
        "mysql_db_query" => array("mysql_escape_string", "mysql_real_escape_string"),
        //
        "mysqli_query" => array("mysqli_escape_string", "mysqli_real_escape_string"),
        "mysqli_real_query" => array("mysqli_escape_string", "mysqli_real_escape_string"),
        "mysqli_master_query" => array("mysqli_escape_string", "mysqli_real_escape_string"),
        "mysqli_multi_query" => array("mysqli_escape_string", "mysqli_real_escape_string"),
        //
        "mysqli_stmt_execute" => array("mysqli_stmt_bind_param"),
        "mysqli_execute" => array("mysqli_stmt_bind_param"),
        //
        "mysqli::query" => array("mysqli::escape_string", "mysqli::real_escape_string"),
        "mysqli::multi_query" => array("mysqli::escape_string", "mysqli::real_escape_string"),
        "mysqli::real_query" => array("mysqli::escape_string", "mysqli::real_escape_string"),
        //
        "mysqli_stmt::execute" => array("mysqli_stmt::bind_param"),
        //
        "db2_exec" => array("db2_escape_string"),
        //
        "pg_query" => array("pg_escape_string","pg_escape_bytea"),
        "pg_send_query"=> array("pg_escape_string","pg_escape_bytea")),
      "XSS" => array(
        //
        "echo" => array(" htmlentities", "htmlspecialchars","strip_tags","urlencode"),
        "print" => array(" htmlentities", "htmlspecialchars","strip_tags","urlencode"),
        "printf" => array(" htmlentities", "htmlspecialchars","strip_tags","urlencode"),
        "die" => array(" htmlentities", "htmlspecialchars","strip_tags","urlencode"),
        "error" => array(" htmlentities", "htmlspecialchars","strip_tags","urlencode"),
        "exit" => array(" htmlentities", "htmlspecialchars","strip_tags","urlencode"),
        //
        "file_put_contents" => array(" htmlentities", "htmlspecialchars","strip_tags","urlencode"),
        "file_get_contents" => array(" htmlentities", "htmlspecialchars","strip_tags","urlencode")),
      );

    /**
     * @param String    $code       Code to be inspected
     */
    public function __construct($code) {
        $this->_parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP5);

        try {
            $stmts = $this->_parser->parse($code);
            echo '<pre>';
            print_r($stmts);
            echo '<h1>Vunerabilities</h1>';
            print_r($this->checkVunerabilities($stmts, array()));
            echo '</pre>';
        } catch (Error $e) {
            echo 'Parse Error: ', $e->getMessage();
        }
    }

    /**
     * @param PhpParser\Node\Expr $expr
     */
    public function searchSinks($expr) {
        $sinks = array();
        # echo $expr->getType() . '<br />';

        if ($expr->getType() === 'Expr_FuncCall') {
            /** @var PhpParser\Node\Expr\FuncCall $expr */
            foreach (array_keys($this->vulnerabilities['SQL']) as $sink) {
                if ($sink === $expr->name->parts[0]) {
                    # Construction of vars used in the sink
                    $vars = array();
                    /** @var PhpParser\Node\Arg $arg */
                    foreach ($expr->args as $arg) {
                        $args = array_push($vars, $arg->value);
                    }

                    $sinks[$expr->getLine()] = new Sink($sink, $expr->getLine(), false, $this->vulnerabilities['SQL'][$sink], $vars);
                }
            }
        }

        return $sinks;
    }

    /**
     * For a given context it checks for sinks within it.
     *
     * @param  String           $context        Program context passed in the PhpParser framework
     * @return array of Sinks                   [description]
     */
    public function checkVunerabilities($context, $earlierVars) {
        $sinks = array();

        /** @var PhpParser\Node\Expr\Assign $line */
        foreach ($context as $line) {
            $sinks = array_merge($sinks, $this->searchSinks($line->expr));
        }

        return $sinks;
    }
}
