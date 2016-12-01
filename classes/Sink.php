<?php

class Sink {
    public $type;
    public $line;
    public $secure;
    public $possibleSanitizations;
    public $vars;
	public $isXss;
	// I use this to bypass the forward check in some conditions. These is mostly to avoid searching for an _SERVER, GET , etc...
	// when they are called in an echo function directly without being sanitazed.
	public $needToCheck;
	// Since we need to print the function that sanitizes the data if no vulnerability is found, we store it in here.
	public $sanitizedFunction;

    public function __construct($type, $line, $secure, $possibleSanitizations, $vars, $xss = false, $needToCheck = true) {
        $this->type = $type;
        $this->line = $line;
        $this->secure = $secure;
        $this->possibleSanitizations = $possibleSanitizations;
        $this->vars = $vars;
		$this->isXss = $xss;
		$this->needToCheck = $needToCheck;
    }
	
	public function setSanitizedFunction($sanitizedFunction)
	{
		$this->sanitizedFunction = $sanitizedFunction;
	}
}