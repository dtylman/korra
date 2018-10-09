package main

import (
	"log"
	"net/http"

	"github.com/dtylman/korra/auth"
	"github.com/dtylman/korra/cookiestore"
	"github.com/dtylman/korra/renderer"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func pageData(c echo.Context, title string) map[string]interface{} {
	data := map[string]interface{}{
		"Title": title,
	}
	user, err := auth.LoggedUser(c)
	if err == nil {
		data["UserName"] = user.Name
		data["UserRole"] = user.Role
	}
	return data
}

func loginPost(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	err := auth.DoLogin(username, password, c)
	if err != nil {
		log.Print(err)
		data := map[string]interface{}{
			"Title": "Login",
			"Error": err,
		}
		return c.Render(http.StatusOK, "login.html", data)
	}
	return c.Redirect(http.StatusFound, "/")
}

func loginGet(c echo.Context) error {
	data := map[string]interface{}{
		"Title": "Login",
	}
	return c.Render(http.StatusOK, "login.html", data)
}

func logoutGet(c echo.Context) error {
	err := auth.Logout(c)
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusFound, "/")
}

func indexGet(c echo.Context) error {
	data := pageData(c, "Korra")
	return c.Render(http.StatusOK, "index.html", data)
}

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

	e.GET("/", indexGet, auth.Middleware)

	e.GET("/login", loginGet)
	e.POST("/login", loginPost)
	e.GET("/logout", logoutGet)

	return e.Start(":8000")
}

func main() {
	err := startServer()
	if err != nil {
		panic(err)
	}

}
