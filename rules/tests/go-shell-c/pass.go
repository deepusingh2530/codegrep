package main
import "os/exec"
func f() { exec.Command("ls", "-l") }
