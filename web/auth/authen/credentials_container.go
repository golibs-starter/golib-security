package authen

// CredentialsContainer Indicates that the implementing
// object contains credentials
type CredentialsContainer interface {

	// EraseCredentials For safety, implementing object might
	// want to erase credentials
	EraseCredentials()
}
