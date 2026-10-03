const { spawn } = require("child_process");

// spawn defaults to no shell and an argument vector. These are all safe, even
// though `branch` and `dir` are interpolated.
function gitLog(branch) {
  return spawn("git", ["log", branch]);
}

function gitLogNoShell(branch) {
  return spawn("git", ["log", branch], { shell: false });
}

function listDir(dir) {
  return spawn("ls", ["-la", dir], { shell: false, cwd: dir });
}
