package main

import (
	"log"
	"net/http"

	"github.com/dtylman/korra/renderer"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
)

func postLogin(c echo.Context) error {
	username := c.FormValue("username")
	sess, _ := session.Get("session", c)
	sess.Values["user"] = username
	sess.Save(c.Request(), c.Response())
	log.Println(username)
	return c.Redirect(http.StatusFound, "/")
}

func login(c echo.Context) error {
	data := map[string]interface{}{
		"Title": "Login",
	}
	return c.Render(http.StatusOK, "login.html", data)
}

func index(c echo.Context) error {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}

	_, ok := sess.Values["user"]
	if !ok {
		return c.Redirect(http.StatusFound, "/login")
	}

	data := map[string]interface{}{
		"Title": "Lala",
	}
	return c.Render(http.StatusOK, "index.html", data)
}

func work() error {
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
	// e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
	// 	TokenLookup: "header:X-XSRF-TOKEN",
	// }))

	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))

	e.Static("assets", "frontend/tabler/assets")
	e.Static("/", "frontend")

	e.GET("/", index)
	e.GET("/login", login)
	e.POST("/login", postLogin)

	return e.Start(":8000")
}

func main() {
	err := work()
	if err != nil {
		panic(err)
	}

}
