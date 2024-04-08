package keyopts

// KeyOptsFactory is a factory for KeyOpts instances
type KeyOptsFactory interface {
	// Create a new KeyOpts from a repository configuration
	NewKeyOpts(cfg interface{}) KeyOpts
}