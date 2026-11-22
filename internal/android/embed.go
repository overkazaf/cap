package android

import _ "embed"

//go:embed bin/cap-redir-arm64
var capRedirBinary []byte

//go:embed bin/cap-companion.apk
var capCompanionAPK []byte

// CapRedirBinary returns the pre-compiled cap-redir binary for Android arm64.
func CapRedirBinary() []byte {
	return capRedirBinary
}

// CapCompanionAPK returns the signed Cap Guard Android Companion APK.
func CapCompanionAPK() []byte {
	return capCompanionAPK
}
