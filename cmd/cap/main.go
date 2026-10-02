package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/overkazaf/cap/internal/cli"
)

//go:embed all:frontend/dist
var frontendAssets embed.FS

func main() {
	cli.SetFrontendAssets(frontendAssets)
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "cap: %v\n", err)
		os.Exit(1)
	}
}
