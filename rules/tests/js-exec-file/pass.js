const { execFile } = require("child_process");

// A quoted executable is a fixed program: this is the safe form the rule's own
// `fix` recommends, so it must not be reported.
function listDir(dir) {
  return execFile("ls", ["-la", dir]);
}

function status() {
  return execFile("git", ["status"]);
}

function version() {
  return execFile("node", ["--version"]);
}
