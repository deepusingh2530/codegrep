public function filter($s) {
  return preg_replace_callback('/(\\w+)/', function ($m) {
    return strtoupper($m[1]);
  }, $s);
}
