package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"

	"github.com/dtylman/gowd"
	"github.com/dtylman/gowd/bootstrap"
	"github.com/dtylman/korra/analyzer"
	"github.com/dtylman/korra/analyzer/assumerole"
	"github.com/dtylman/korra/analyzer/cloudtrail"
)

type app struct {
	body        *gowd.Element
	em          gowd.ElementsMap
	content     *gowd.Element
	fetchCard   *gowd.Element
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
	a.em["menubutton-fetch"].OnEvent(gowd.OnClick, a.menuButttonFetchClicked)
	a.em["menubutton-analyze"].OnEvent(gowd.OnClick, a.menuButttonAnalyzeClicked)
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

/*
 <table class="table align-items-center table-dark table-flush" id="table-assume-roles">
                        <thead class="thead-dark">
                            <tr>
                                <th scope="col">Name</th>
                                <th scope="col">ARN</th>
                                <th scope="col">Issues</th>
                            </tr>
                        </thead>
                        <tbody id="tbody-assume-role">
                        </tbody>
                    </table>
                <!-- </div>
                <div class="table-responsive"> -->
                        <table class="table align-items-center table-dark table-flush" id="table-assume-roles">
                            <thead class="thead-dark">
                                <tr>
                                    <th scope="col">Name</th>
                                    <th scope="col">ARN</th>
                                    <th scope="col">Issues</th>
                                </tr>
                            </thead>
                        </table>
                        <table class="table align-items-center table-dark table-flush">
                                <tr>
                                <th scope="col">Time</th>
                                <th scope="col">Type</th>
                                <th scope="col">IP</th>
                                <th scope="col">User Agent</th>
                                </tr>
                        </table>
					</div>*/

func (a *app) menuButttonAnalyzeClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.em["span-total-read"].SetText(fmt.Sprintf("%v", analyzer.TotalRead))
	a.em["span-assume-role-session"].SetText(fmt.Sprintf("%v", len(assumerole.Sessions)))
	errorEvents := cloudtrail.ErrorEvents()
	a.em["button-errros"].SetText(fmt.Sprintf("%v", len(errorEvents)))

	tableErrors := bootstrap.NewTable("table align-items-center table-flush")
	tableErrors.Head.SetClass("thead-dark")
	tableErrors.AddHeader("Name").SetAttribute("scope", "col")
	tableErrors.AddHeader("Type").SetAttribute("scope", "col")
	tableErrors.AddHeader("Error").SetAttribute("scope", "col")
	a.em["div-table-errors"].SetElement(tableErrors.Element)
	for _, ee := range errorEvents {
		row := tableErrors.AddRow()
		// cell := gowd.NewElement("td")
		// link := bootstrap.NewLinkButton(ee.Name)
		// row.OnEvent(gowd.OnClick, a.errorLinkButtonClicked)
		row.AddCells(ee.Name, ee.Type, ee.ErrorCode)
		row.Object, _ = ee.JSONString()
		row.OnEvent(gowd.OnClick, a.errorLinkButtonClicked)
	}

	a.em["div-table-assume-roles"].RemoveElements()
	for _, ars := range assumerole.Sessions {
		tar := bootstrap.NewTable("table align-items-center table-flush")
		tar.Head.SetClass("thead-dark")
		tar.AddHeader("Name").SetAttribute("scope", "col")
		tar.AddHeader("ARN").SetAttribute("scope", "col")
		tar.AddHeader("Issues").SetAttribute("scope", "col")
		a.em["div-table-assume-roles"].AddElement(tar.Element)
		row := tar.AddRow()
		row.AddCells(ars.Name, ars.AssumedRoleARN, fmt.Sprintf("%v", ars.Issues))

		tev := bootstrap.NewTable("table align-items-center table-flush")
		tev.Head.SetClass("thead-dark")
		tev.AddHeader("Time").SetAttribute("scope", "col")
		tev.AddHeader("Type").SetAttribute("scope", "col")
		tev.AddHeader("IP").SetAttribute("scope", "col")
		tev.AddHeader("User Agent").SetAttribute("scope", "col")
		a.em["div-table-assume-roles"].AddElement(tev.Element)
		for _, e := range ars.Events {
			row := tev.AddRow()
			row.AddCells(fmt.Sprintf("%v", e.Time), e.Type, e.SourceIPAddress, e.UserAgent)
		}
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
	err := analyzer.LoadAndAnalyze(a.onFetchProgress)
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
		return
	}
	html := `<p class="mt-3 mb-0 text-muted text-sm">
	<span class="text-success mr-2"> <i class="fa fa-chart-line"></i> %v </span>
	<span class="text-nowrap"> sessions loaded.</span></p>`
	a.em["fetch-card-body"].AddHTML(fmt.Sprintf(html, len(assumerole.Sessions)), nil)
	link := bootstrap.NewLinkButton("Analyze")
	link.SetClass("btn btn-sm btn-primary")
	link.OnEvent(gowd.OnClick, a.menuButttonAnalyzeClicked)
	a.em["fetch-card-body"].AddElement(link)
}

func (a *app) buttonLoadEventsClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.em["button-loadevents"].SetClass("disabled")
	analyzer.Options.Region = a.em["input-region"].GetValue()
	var err error
	analyzer.Options.MaxOnlineEvents, err = strconv.Atoi(a.em["input-maxevents"].GetValue())
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
