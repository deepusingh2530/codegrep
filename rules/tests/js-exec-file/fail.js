const { execFile } = require("child_process");

// The program path itself is user-controlled.
function runBinary(bin, args) {
  return execFile(bin, args);
}
