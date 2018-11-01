package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"

	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/analysis/char/html"
	"github.com/dtylman/gowd"
	"github.com/dtylman/gowd/bootstrap"
	"github.com/dtylman/korra/analyzer"
	"github.com/dtylman/korra/analyzer/assumerole"
	"github.com/dtylman/korra/analyzer/cloudtrail"
)

type app struct {
	body           *gowd.Element
	em             gowd.ElementsMap
	content        *gowd.Element
	loadPage       *gowd.Element
	sessionsPage   *gowd.Element
	errorsPage     *gowd.Element
	searchPage     *gowd.Element
	assumerolePage *gowd.Element
	indexer        *analyzer.BleveAnalyzer
}

func newApp() (*app, error) {
	a := new(app)
	var err error
	a.em = gowd.NewElementMap()
	a.body = bootstrap.NewContainer(true)

	a.loadPage, err = a.loadFromTemplate("load.html")
	if err != nil {
		return nil, err
	}
	a.sessionsPage, err = a.loadFromTemplate("sessions.html")
	if err != nil {
		return nil, err
	}
	a.errorsPage, err = a.loadFromTemplate("errors.html")
	if err != nil {
		return nil, err
	}
	a.assumerolePage, err = a.loadFromTemplate("assumerole.html")
	if err != nil {
		return nil, err
	}
	a.searchPage, err = a.loadFromTemplate("search.html")
	if err != nil {
		return nil, err
	}
	err = a.addFromTemplate(a.body, "body.html")
	if err != nil {
		return nil, err
	}
	a.content = a.em["main-content"]

	a.em["button-search-go"].OnEvent(gowd.OnClick, a.buttonSearchClicked)
	a.em["button-loadevents"].OnEvent(gowd.OnClick, a.buttonLoadEventsClicked)
	a.em["menubutton-load"].OnEvent(gowd.OnClick, a.menuButttonLoadClicked)
	a.em["menubutton-sessions"].OnEvent(gowd.OnClick, a.menuButttonSessionsClicked)
	a.em["menubutton-search"].OnEvent(gowd.OnClick, a.menuButttonSearchClicked)

	a.em["button-errros"].OnEvent(gowd.OnClick, a.menuButttonErrorsClicked)
	a.em["menubutton-errors"].OnEvent(gowd.OnClick, a.menuButttonErrorsClicked)
	a.content.SetElement(a.loadPage)
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
	err := cloudtrail.LoadFromFile()
	if err != nil {
		return err
	}
	analyzer.AddAnalyzer(new(analyzer.AssumeRoleSessionAnalyzer))
	a.indexer, err = analyzer.NewBleveAnalyzer("korra.db")
	if err != nil {
		return err
	}
	defer a.indexer.Close()
	analyzer.AddAnalyzer(a.indexer)

	err = analyzer.Analyze()
	if err != nil {
		return err
	}

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

func (a *app) menuButttonSearchClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.content.SetElement(a.searchPage)
}

func (a *app) menuButttonErrorsClicked(sender *gowd.Element, event *gowd.EventElement) {

	tableErrors := bootstrap.NewTable("table align-items-center table-flush")
	tableErrors.AddHeader("Name").SetAttribute("scope", "col")
	tableErrors.AddHeader("Type").SetAttribute("scope", "col")
	tableErrors.AddHeader("Error").SetAttribute("scope", "col")
	tableErrors.Head.SetAttribute("scope", "row")
	a.em["div-table-errors"].SetElement(tableErrors.Element)
	for _, ee := range cloudtrail.ErrorEvents() {
		row := tableErrors.AddRow()
		// cell := gowd.NewElement("td")
		// link := bootstrap.NewLinkButton(ee.Name)
		// row.OnEvent(gowd.OnClick, a.errorLinkButtonClicked)
		row.AddCells(ee.Name, ee.Type, ee.ErrorCode)
		row.Object, _ = ee.JSONString()
		row.OnEvent(gowd.OnClick, a.errorLinkButtonClicked)
	}

	a.content.SetElement(a.errorsPage)
}

func (a *app) sessionClicked(sender *gowd.Element, event *gowd.EventElement) {
	script := `var nodes = new vis.DataSet([
		{ id: 1, label: 'User: URI', title: "Amazon" },
		{ id: 2, label: 'Amazon STS' },
	]);

	var edges = new vis.DataSet([
		{ from: 2, to: 1 , label: "got it", length: 400  },
		{ from: 1, to: 2, label: "test", length: 400}
	]);

	var container = document.getElementById('mynetwork');
	var data = {
		nodes: nodes,
		edges: edges
	};
	var options = {
		layout: {
			hierarchical: {
				direction: "UD"
			}
		}
	};
	var network = new vis.Network(container, data, options);`
	gowd.ExecJS(script)
	script = `var container = document.getElementById('visualization');`
	sess := sender.Object.(assumerole.Session)
	script += `var items = [`
	for i, e := range sess.Events {
		script += fmt.Sprintf(`{id: %v, content: '%v', start: '%v'},`, i, e.SourceIPAddress, e.Time)

	}
	script += `];
	var dataset = new vis.DataSet(items);
	var options = {	};
	var timeline = new vis.Timeline(container, items, options);`
	gowd.ExecJS(script)
	a.content.SetElement(a.assumerolePage)
	// a.content.SetElement(gowd.NewText(fmt.Sprintf("%v", sender.Object)))
}

func (a *app) menuButttonSessionsClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.em["span-total-read"].SetText(fmt.Sprintf("%v", len(cloudtrail.Events)))
	a.em["span-assume-role-session"].SetText(fmt.Sprintf("%v", len(assumerole.Sessions)))
	errorEvents := cloudtrail.ErrorEvents()
	a.em["button-errros"].SetText(fmt.Sprintf("%v", len(errorEvents)))

	a.em["div-table-assume-roles"].RemoveElements()
	tar := bootstrap.NewTable("table align-items-center table-flush")
	tar.AddHeader("Time").SetAttribute("scope", "col")
	tar.AddHeader("Name").SetAttribute("scope", "col")
	tar.AddHeader("ARN").SetAttribute("scope", "col")
	tar.Head.SetAttribute("scope", "row")
	a.em["div-table-assume-roles"].AddElement(tar.Element)

	for _, ars := range assumerole.Sessions {
		link := bootstrap.NewLinkButton(ars.Name)
		link.Object = ars
		link.OnEvent(gowd.OnClick, a.sessionClicked)
		cell := gowd.NewElement("td")
		row := tar.AddRow()
		row.AddCells(ars.Time())
		cell.AddElement(link)
		row.AddElement(cell)
		row.AddCells(ars.AssumedRoleARN)
	}

	//gowd.ExecJS("$('#table-errors').DataTable();")
	a.content.SetElement(a.sessionsPage)
}

func (a *app) menuButttonLoadClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.content.SetElement(a.loadPage)
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
	link.OnEvent(gowd.OnClick, a.menuButttonSessionsClicked)
	a.em["fetch-card-body"].AddElement(link)
}

func (a *app) buttonSearchClicked(sender *gowd.Element, event *gowd.EventElement) {
	input := a.em["input-search"]
	term := input.GetValue()
	input.AutoFocus()
	input.SetValue("")
	query := bleve.NewQueryStringQuery(term)
	req := bleve.NewSearchRequest(query)
	req.Highlight = bleve.NewHighlightWithStyle(html.Name)
	sr, err := a.indexer.Index.Search(req)
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
		return
	}

	div := a.em["div-results"]
	div.RemoveElements()
	div.AddHTML(sr.String(), nil)

	for _, hit := range sr.Hits {
		dr := gowd.NewElement("div")
		dr.AddHTML(hit.String(), nil)
		dr.AddHTML("</br>", nil)
		//div.AddElement(gowd.NewText(fmt.Sprintf("%v", doc.Document)))
		div.AddElement(dr)
	}

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
