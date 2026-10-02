package main

import (
	"fmt"
	"os"

	"github.com/nongjiawu/cap/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "cap: %v\n", err)
		os.Exit(1)
	}
}
