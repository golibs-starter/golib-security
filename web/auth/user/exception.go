package user

import (
	"github.com/golibs-starter/golib/exception"
	"net/http"
)

var (
	NotFound = exception.New(http.StatusNotFound, "User not found")
)
