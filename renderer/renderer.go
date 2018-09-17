package renderer

import (
	"io"
	"log"

	"html/template"

	"github.com/labstack/echo"
)

// Renderer is an html/template renderer for korra resources
type Renderer struct {
	templates *template.Template
	funcs     template.FuncMap
}

// NewRenderer returns a new renderer
func NewRenderer(glob string) (*Renderer, error) {
	r := new(Renderer)
	r.funcs = make(template.FuncMap)
	r.funcs["text"] = r.text
	var err error
	r.templates, err = template.New("root").Funcs(r.funcs).ParseGlob(glob)
	if err != nil {
		return nil, err
	}
	for _, l := range r.templates.Templates() {
		log.Printf("Loaded template: '%s'", l.Name())
	}
	return r, nil
}

// Render renders a template document
func (r *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

func (r *Renderer) text(txt string) string {
	return txt
}
