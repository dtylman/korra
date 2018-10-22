package main

import (
	"github.com/dtylman/korra/auth"
	"github.com/dtylman/korra/cookiestore"
	"github.com/dtylman/korra/renderer"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func startServer() error {
	e := echo.New()
	renderer, err := renderer.NewRenderer("frontend/templates/*.html")
	if err != nil {
		return err
	}
	e.Renderer = renderer

	logconf := middleware.DefaultLoggerConfig
	logconf.Format = "${time_rfc3339_nano} ${id} ${remote_ip} ${host} ${method} ${uri} ${status} ${error} \n"
	e.Use(middleware.LoggerWithConfig(logconf))

	e.Use(middleware.Recover())

	e.Use(middleware.Secure())

	// e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
	// 	TokenLookup: "header:X-XSRF-TOKEN",
	// }))

	cookiestore.MaxAge(20 * 60)

	e.Use(cookiestore.Middleware())

	e.Static("assets", "frontend/tabler/assets")
	e.Static("/", "frontend")

	e.GET("/", handleHomeGet, auth.Middleware)
	e.GET("/settings", handleSettingsGet, auth.Middleware)
	e.GET("/roles", handleRolesGet, auth.Middleware)

	e.GET("/login", handleLoginGet)
	e.POST("/login", handleLoginPost)
	e.GET("/logout", handleLogoutGet)

	return e.Start(":8000")
}

func main() {
	err := startServer()
	if err != nil {
		panic(err)
	}

}
