package user

// Service Core interface which loads user-specific data.
type Service interface {

	// GetByUsername Locates the user based on the username.
	GetByUsername(username string) (Details, error)
}
