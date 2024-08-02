package helper

// ResponseCode type and constants
type ResponseCode string

const (
	OK                   ResponseCode = "2000000"
	UNAUTHORIZED         ResponseCode = "4010000"
	INVALID_FIELD_FORMAT ResponseCode = "4000001"
	LOGIN_FAILED         ResponseCode = "4000002"
	SERVER_GENERAL_ERROR ResponseCode = "5000000"
)

var responseMessages = map[ResponseCode]string{
	OK:                   "OK",
	UNAUTHORIZED:         "Unauthorized",
	INVALID_FIELD_FORMAT: "Invalid field format",
	LOGIN_FAILED:         "Username or password is incorrect",
	SERVER_GENERAL_ERROR: "General error",
}

func (rc ResponseCode) Message() string {
	return responseMessages[rc]
}
