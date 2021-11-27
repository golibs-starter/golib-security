package user

import (
	"gitlab.com/golibs-starter/golib/exception"
	"net/http"
)

var (
	NotFound = exception.New(http.StatusNotFound, "User not found")
)
