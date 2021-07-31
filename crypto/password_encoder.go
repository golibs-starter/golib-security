package crypto

// PasswordEncoder Interface for encoding password
type PasswordEncoder interface {

	// Encode the raw password to encoded password.
	Encode(rawPassword string) string

	// Matches the encoded password obtained from storage and the submitted raw
	// password after it too is encoded. Returns true if the passwords match,
	// false if they do not.
	Matches(rawPassword string, encodedPassword string) bool
}
