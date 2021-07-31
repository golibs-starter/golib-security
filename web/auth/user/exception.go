package user

import (
	"gitlab.id.vin/vincart/golib/exception"
	"net/http"
)

var (
	NotFound = exception.New(http.StatusNotFound, "User not found")
)
