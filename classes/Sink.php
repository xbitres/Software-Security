<?php

class Sink {
    public $type;
    public $line;
    public $secure = true;
    public $possibleSanitizations;
    public $vars;

    public function __construct($type, $line, $secure, $possibleSanitizations, $vars) {
        $this->type = $type;
        $this->line = $line;
        $this->secure = $secure;
        $this->possibleSanitizations = $possibleSanitizations;
        $this->vars = $vars;
    }
}