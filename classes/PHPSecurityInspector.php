<?php

require_once 'vendor/PhpParser/Autoloader.php';

require_once 'Sink.php';

PhpParser\Autoloader::register();

use PhpParser\Error;
use PhpParser\ParserFactory;

class PHPSecurityInspector {
    private $_parser;
    private $_entryPoints = array(
        "SQL" => array(
            "_GET",
            "_POST",
            "_COOKIE",
            "_REQUEST",
            "HTTP_GET_VARS",
            "HTTP_POST_VARS",
            "HTTP_COOKIE_VARS",
            "HTTP_REQUEST_VARS",
        ),
        "XSS" => array(
            "_GET",
            "_POST",
            "_COOKIE",
            "_REQUEST",
            "HTTP_GET_VARS",
            "HTTP_POST_VARS",
            "HTTP_COOKIE_VARS",
            "HTTP_REQUEST_VARS",
            "_FILES",
            "_SERVERS",
        ),
    );
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
    public function searchSQLSinks($expr) {
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

                    $sinks[$expr->getLine()] = new Sink($sink, $expr->getLine(), true, $this->vulnerabilities['SQL'][$sink], $vars);
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
            $sks = array();
            if ($line->getType() === 'Expr_Assign') {
                $sks = $this->searchSQLSinks($line->expr);
            } else if ($line->getType() === 'Expr_FuncCall') {
                $sks = $this->searchSQLSinks($line);
            }

            $sinks = array_merge($sinks, $sks);
        }


        $varsOfVars = array(); # Stack containing variables related to the sink

        /** @var Sink $sink */
        foreach ($sinks as $sink) {
            $varsOfVars = $sink->vars;

            while (!empty($varsOfVars)) {
                /** @var \PhpParser\Node\Expr\Variable $var */
                $var = array_pop($varsOfVars);

                echo $var->name . '<br>';

                var_dump($this->variableSecure($var,$context, $sink->possibleSanitizations));
                var_dump($this->getConnectedVars($var, $context));

                if (!$this->variableSecure($var,$context, $sink->possibleSanitizations)) {
                    if ($connectedVars = $this->getConnectedVars($var, $context)) {
                        $varsOfVars = array_merge($connectedVars, $varsOfVars);
                    } else {
                        $sink->secure = false;
                    }
                }
            }

        }

        return $sinks;
    }

    /**
     * @param \PhpParser\Node\Expr\Variable $var
     * @param $context
     * @return bool
     */
    private function getConnectedVars($var, $context) {
        $connectedVars = array();

        /** @var \PhpParser\Node\Expr\Assign $line */
        foreach ($context as $line) { # Search in the context for the variable
            if ($line->getType() === 'Expr_Assign') {
                if ($line->var->name === $var->name) {
                    # If we found an assignment changing the variable we search for the connected vars
                    if ($line->expr->getType() === 'Scalar_Encapsed') {
                        /** @var \PhpParser\Node $node */
                        foreach ($line->expr->parts as $node) {

                            if ($node->getType() === 'Expr_Variable') {
                                array_push($connectedVars, $node);
                            } else if ($node->getType() === 'Expr_ArrayDimFetch') {
                                array_push($connectedVars, $node->var);
                            }
                        }
                    } else if ($line->expr->getType() === 'Expr_BinaryOp_Concat') {
                        $exprTmp = $line->expr;
                        do {
                            if ($exprTmp->right->getType() === 'Expr_Variable') {
                                array_push($connectedVars, $exprTmp->right);
                            } else if ($exprTmp->right->getType() === 'Expr_ArrayDimFetch') {
                                array_push($connectedVars, $exprTmp->right->var);
                            }

                            if ($exprTmp->left->getType() === 'Expr_Variable') {
                                array_push($connectedVars, $exprTmp->right);
                            } else if ($exprTmp->left->getType() === 'Expr_ArrayDimFetch') {
                                array_push($connectedVars, $exprTmp->right->var);
                            }

                            $exprTmp = $exprTmp->left;
                        } while ($exprTmp->getType() === 'Expr_BinaryOp_Concat');
                    }
                }
            }
        }

        if (empty($connectedVars))
            return false;
        else
            return $connectedVars;
    }

    /**
     * @param \PhpParser\Node\Expr\Variable $var
     * @param $context
     * @return bool
     */
    private function variableSecure($var, $context, $sanitizations) {
        # Verificar se var nao tem connected vars
        # Caso tenha connected vars entao não é secure
        # Caso não tenha então:
            # Verificar se var é entry point
        if (empty($this->getConnectedVars($var, $context))) {
            if (!$this->variableInEntryPoint($var, $context)) {
                return true;
            } else if ($this->variableSanitized($var, $context, $sanitizations)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param $var
     * @param $context
     * @param array $sanitizations
     * @return bool
     */
    private function variableSanitized($var, $context, $sanitizations) {
        foreach ($context as $line) {
            if ($line->getType() === 'Expr_Assign') {
                if ($line->var->name === $var->name) {
                    # Verificar se os parametros do assignment nao sao entrypoints
                    if ($line->expr->getType() === 'Expr_FuncCall') {
                        if (in_array($line->expr->name->parts[0], $sanitizations)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * @param \PhpParser\Node\Expr\Variable $var
     * @param $context
     * @return bool
     */
    private function variableInEntryPoint($var, $context) {
        if (in_array($var->name, $this->_entryPoints['SQL'])) {
            return true;
        }

        /** @var \PhpParser\Node\Expr\Assign $line */
        foreach ($context as $line) {
            if ($line->getType() === 'Expr_Assign') {
                if ($line->var->name === $var->name) {
                    # Verificar se os parametros do assignment nao sao entrypoints
                    if ($line->expr->getType() === 'Expr_ArrayDimFetch') {
                        if (in_array($line->expr->var->name, $this->_entryPoints['SQL'])) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }
}
