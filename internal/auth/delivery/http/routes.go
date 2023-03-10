package http

import (
	"github.com/labstack/echo/v4"
	"go-clean-architecture-rest/internal/auth"
	"go-clean-architecture-rest/internal/middlewares"
)

// MapAuthRoutes Map auth routes
func MapAuthRoutes(authGroup *echo.Group, h auth.Handlers, mw *middlewares.MiddlewareManager) {
	authGroup.POST("/register", h.Register())
	authGroup.POST("/login", h.Login())
	//authGroup.POST("/logout", h.Logout())
	//authGroup.GET("/find", h.FindByName())
	//authGroup.GET("/all", h.GetUsers())
	authGroup.Use(mw.AuthJWTMiddleware)
	//authGroup.Use(mw.AuthSessionMiddleware)
	authGroup.GET("/csrf-token", h.GetCSRFToken())
	authGroup.Use(mw.CSRF)
	authGroup.GET("/me", h.GetMe())
	//authGroup.POST("/:user_id/avatar", h.UploadAvatar(), mw.CSRF)
	ownerOrAdminGroup := authGroup.Group("", mw.OwnerOrAdminMiddleware())
	ownerOrAdminGroup.GET("/:user_id", h.GetUserByID()) // should use mw.OwnerOrAdminMiddleware()
	adminGroup := authGroup.Group("", mw.RoleBasedAuthMiddleware([]string{"admin"}))
	adminGroup.GET("/all", h.GetUsers())
	//authGroup.PUT("/:user_id", h.Update(), mw.OwnerOrAdminMiddleware(), mw.CSRF)
	//authGroup.DELETE("/:user_id", h.Delete(), mw.CSRF, mw.RoleBasedAuthMiddleware([]string{"admin"}))
}
