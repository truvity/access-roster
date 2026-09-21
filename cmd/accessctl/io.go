package main

import "os"

// stdout is a variable so a test can read what a command printed.
var stdout = os.Stdout

// stderr is the other half, for a command that reports what it did
// without putting it where a caller capturing stdout would pick it up.
var stderr = os.Stderr
