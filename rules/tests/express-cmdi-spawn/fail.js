const { spawn } = require("child_process");

// shell: true runs the string through a shell, so user input reaches it.
function runShell(cmd) {
  return spawn(cmd, { shell: true });
}

function runWithArgs(cmd, args) {
  return spawn(cmd, args, { shell: true });
}
