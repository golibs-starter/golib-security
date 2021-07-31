package user

type InMemUserDetailsService struct {
	users map[string]Details
}

func NewInMemUserDetailsService(userDetails []Details) *InMemUserDetailsService {
	mapUsers := make(map[string]Details)
	for _, userDetail := range userDetails {
		mapUsers[userDetail.Username()] = userDetail
	}
	return &InMemUserDetailsService{mapUsers}
}

func (i InMemUserDetailsService) GetByUsername(username string) (Details, error) {
	user, ok := i.users[username]
	if !ok {
		return nil, NotFound
	}
	return user, nil
}
