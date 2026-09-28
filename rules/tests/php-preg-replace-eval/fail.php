public function filter($s) {
  return preg_replace('/(\\w+)/e', 'strtoupper("$1")', $s);
}
