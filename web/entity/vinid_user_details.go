package entity

type VinIdUserDetails struct {
	UserId          string
	DeviceId        string
	DeviceSessionId string
	Roles           []string
}

func (v VinIdUserDetails) GetUserId() string {
	return v.UserId
}
