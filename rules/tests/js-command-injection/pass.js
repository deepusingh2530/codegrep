const { execFile } = require("child_process");
const { spawn } = require("child_process");
const fs = require("fs");

// execFile with a static executable and an argument array is the safe form.
function list(dir) {
  return execFile("ls", ["-la", dir]);
}

// spawn with a static command and argument array is also safe.
function stat(dir) {
  return spawn("stat", [dir]);
}

function read(path) {
  return fs.readFileSync(path, "utf8");
}
