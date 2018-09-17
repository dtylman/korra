package main

import (
	"net/http"

	"github.com/dtylman/korra/renderer"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func login(c echo.Context) error {
	data := map[string]interface{}{
		"Title": "Login",
	}
	return c.Render(http.StatusOK, "login.html", data)
}

func index(c echo.Context) error {
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
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "header:X-XSRF-TOKEN",
	}))

	e.Static("assets", "frontend/tabler/assets")
	e.Static("DataTables", "frontend/datatables")

	e.GET("/", index)
	e.GET("/login", login)
	return e.Start(":8000")
}

func main() {
	err := work()
	if err != nil {
		panic(err)
	}

}
