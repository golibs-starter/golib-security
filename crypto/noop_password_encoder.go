package crypto

// NoOpPasswordEncoder A password encoder that does nothing.
// Useful for testing where working with plain text
// passwords may be preferred.
type NoOpPasswordEncoder struct {
}

func NewNoOpPasswordEncoder() *NoOpPasswordEncoder {
	return &NoOpPasswordEncoder{}
}

func (n NoOpPasswordEncoder) Encode(rawPassword string) string {
	return rawPassword
}

func (n NoOpPasswordEncoder) Matches(rawPassword string, encodedPassword string) bool {
	return rawPassword == encodedPassword
}
