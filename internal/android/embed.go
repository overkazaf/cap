package android

import _ "embed"

//go:embed bin/cap-redir-arm64
var capRedirBinary []byte

// CapRedirBinary returns the pre-compiled cap-redir binary for Android arm64.
func CapRedirBinary() []byte {
	return capRedirBinary
}
