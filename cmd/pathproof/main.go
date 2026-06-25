package main

import (
	"fmt"
	"io"
	"os"
)

const version = "pathproof dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing command")
		fmt.Fprintln(stderr)
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "version":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "version accepts no arguments, got %q\n", args[1:])
			fmt.Fprintln(stderr)
			printUsage(stderr)
			return 2
		}
		fmt.Fprintln(stdout, version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		fmt.Fprintln(stderr)
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: pathproof version")
}
