package main
import "os/exec"
func f() { exec.Command("sh", "-c", userCmd) }
