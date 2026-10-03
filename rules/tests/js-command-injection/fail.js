// Single-argument exec is the common command-injection sink and must be caught.
// This file deliberately contains no other comma-bearing call: before the fix,
// `exec($VAR, ...)` required a trailing comma, so this single call was missed.
const { exec } = require("child_process");
function run(req) {
  return exec(req.query.cmd);
}
