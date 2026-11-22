package buildinfo

// version is set at build time by release automation. Keep the default
// explicit rather than "dev" so standalone local builds are identifiable.
var version = "0.0.0-local"

// Version returns the immutable version embedded into the binary.
func Version() string {
	if version == "" {
		return "0.0.0-local"
	}
	return version
}
