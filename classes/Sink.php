<?php

class Sink {
    public $type;
    public $line;
    public $secure = true;
    public $possibleSanitizations;
    public $vars;
	public $isXss;

    public function __construct($type, $line, $secure, $possibleSanitizations, $vars, $xss = false) {
        $this->type = $type;
        $this->line = $line;
        $this->secure = $secure;
        $this->possibleSanitizations = $possibleSanitizations;
        $this->vars = $vars;
		$this->isXss = $xss;
    }
}