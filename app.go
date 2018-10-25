package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"

	"github.com/dtylman/gowd"
	"github.com/dtylman/gowd/bootstrap"
	"github.com/dtylman/korra/awsclient"
	"github.com/dtylman/korra/events"
)

type app struct {
	body        *gowd.Element
	em          gowd.ElementsMap
	content     *gowd.Element
	fetchCard   *gowd.Element
	tableCard   *gowd.Element
	analyzeCard *gowd.Element
}

func newApp() (*app, error) {
	a := new(app)
	a.em = gowd.NewElementMap()
	a.body = bootstrap.NewContainer(true)
	var err error
	a.fetchCard, err = a.loadFromTemplate("fetch.html")
	if err != nil {
		return nil, err
	}
	a.tableCard, err = a.loadFromTemplate("table.html")
	if err != nil {
		return nil, err
	}
	a.analyzeCard, err = a.loadFromTemplate("analyze.html")
	if err != nil {
		return nil, err
	}
	err = a.addFromTemplate(a.body, "body.html")
	if err != nil {
		return nil, err
	}
	a.content = a.em["main-content"]

	a.em["button-loadevents"].OnEvent(gowd.OnClick, a.buttonLoadEventsClicked)
	a.em["menubutton_fetch"].OnEvent(gowd.OnClick, a.menuButttonFetchClicked)
	a.em["menubutton_analyze"].OnEvent(gowd.OnClick, a.menuButttonAnalyzeClicked)
	a.content.SetElement(a.fetchCard)
	return a, nil
}

func (a *app) loadFromTemplate(name string) (*gowd.Element, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return gowd.ParseElement(string(data), a.em)
}

func (a *app) addFromTemplate(parent *gowd.Element, name string) error {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return err
	}
	elems, err := gowd.ParseElements(strings.NewReader(string(data)), a.em)
	if err != nil {
		return err
	}
	for _, elem := range elems {
		parent.AddElement(elem)
	}
	return nil
}

func (a *app) run() error {
	//start the ui loop
	return gowd.Run(a.body)
}

//shows a modal dialog with the provided title and content
func (a *app) showModal(title string, body *gowd.Element) {
	a.em["modal-title"].SetText(title)
	a.em["modal-body"].SetElement(body)
	gowd.ExecJS(`$('#modal').modal('show');`)
}

func (a *app) errorLinkButtonClicked(sender *gowd.Element, event *gowd.EventElement) {
	code := gowd.NewElement("code")
	code.SetText(fmt.Sprintf("%v", sender.Object))
	a.showModal("Error event", code)
}

func (a *app) menuButttonAnalyzeClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.em["span-total-read"].SetText(fmt.Sprintf("%v", awsclient.TotalRead))
	a.em["span-assume-role-session"].SetText(fmt.Sprintf("%v", len(events.Sessions)))
	a.em["button-errros"].SetText(fmt.Sprintf("%v", len(events.ErrorEvents)))
	tbodyErrors := a.em["tbody_errors"]
	tbodyErrors.RemoveElements()
	for _, ee := range events.ErrorEvents {
		row := bootstrap.NewTableRow()
		cell := gowd.NewElement("td")
		link := bootstrap.NewLinkButton(ee.Name)
		link.Object, _ = ee.JSONString()
		link.OnEvent(gowd.OnClick, a.errorLinkButtonClicked)
		cell.AddElement(link)
		row.AddElement(cell)
		row.AddCells(ee.Type, ee.ErrorCode)
		tbodyErrors.AddElement(row.Element)
	}
	//gowd.ExecJS("$('#table-errors').DataTable();")
	a.content.SetElement(a.analyzeCard)
}

func (a *app) menuButttonFetchClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.content.SetElement(a.fetchCard)
}

//loads and analyzes events
func (a *app) loadEvents() {
	btnstop := a.em["button-loadevents-stop"]
	btnstop.UnsetClass("disabled")
	log.SetOutput(a)
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	defer func() {
		a.em["button-loadevents"].UnsetClass("disabled")
		btnstop.SetClass("disabled")
		a.body.Render()
	}()
	err := awsclient.Analyze(a.onFetchProgress)
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
		return
	}
	html := `<p class="mt-3 mb-0 text-muted text-sm">
	<span class="text-success mr-2"> <i class="fa fa-chart-line"></i> %v </span>
	<span class="text-nowrap"> sessions loaded.</span></p>`
	a.em["fetch-card-body"].AddHTML(fmt.Sprintf(html, len(events.Sessions)), nil)
	link := bootstrap.NewLinkButton("Analyze")
	link.SetClass("btn btn-sm btn-primary")
	link.OnEvent(gowd.OnClick, a.menuButttonAnalyzeClicked)
	a.em["fetch-card-body"].AddElement(link)
}

func (a *app) buttonLoadEventsClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.em["button-loadevents"].SetClass("disabled")
	awsclient.Options.Region = a.em["input-region"].GetValue()
	var err error
	awsclient.Options.MaxOnlineEvents, err = strconv.Atoi(a.em["input-maxevents"].GetValue())
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
		return
	}
	progressRow := a.em["progress-row"]
	progressRow.RemoveElements()
	err = a.addFromTemplate(progressRow, "progress.html")
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
		return
	}

	go a.loadEvents()
}

//onFetchProgress handler for when fetch progress needs to be updated
func (a *app) onFetchProgress(value int, total int) {
	var percent int
	if total == 0 {
		percent = 0
	} else {
		percent = 100 * value / total
	}
	a.em["span_progress_percentage"].SetText(fmt.Sprintf("%v%%", percent))
	a.em["progress-bar-fetch"].SetAttribute("style", fmt.Sprintf("width: %v%%;", percent))
}

//Write is used for displaying `log` messages
func (a *app) Write(p []byte) (n int, err error) {
	a.em["span_progress"].SetText(string(p))
	a.body.Render()
	return len(p), nil
}
