package auth

import "github.com/labstack/echo/v4"

// Handlers Auth HTTP Handlers interface
type Handlers interface {
	Register() echo.HandlerFunc
	Login() echo.HandlerFunc
	GetMe() echo.HandlerFunc
	GetUserByID() echo.HandlerFunc
	GetCSRFToken() echo.HandlerFunc
	GetUsers() echo.HandlerFunc
	//Logout() echo.HandlerFunc
	//Update() echo.HandlerFunc
	//Delete() echo.HandlerFunc
	//FindByName() echo.HandlerFunc
	//UploadAvatar() echo.HandlerFunc
	//GetCSRFToken() echo.HandlerFunc
}
