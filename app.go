package main

import (
	"encoding/base64"
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
	defer cloudtrail.SaveToFile()
	analyzer.AddAnalyzer(new(assumerole.SessionAnalyzer))
	a.indexer, err = analyzer.NewBleveAnalyzer("korra.db")
	if err != nil {
		return err
	}
	defer a.indexer.Close()
	analyzer.AddAnalyzer(a.indexer)
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
	a.em["div-event"].RemoveElements()
	a.em["div-event"].AddHTML(fmt.Sprintf("<code>%v</code>", sender.Object), nil)
	gowd.ExecJS("hljs.highlightBlock(document.getElementById('div-event'));")
	gowd.ExecJS("$('#table-errors').DataTable();")
}

func (a *app) menuButttonSearchClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.content.SetElement(a.searchPage)
}

func (a *app) menuButttonErrorsClicked(sender *gowd.Element, event *gowd.EventElement) {

	tableErrors := bootstrap.NewTable("table align-items-center table-flush")
	tableErrors.SetID("table-errors")
	tableErrors.AddHeader("Name").SetAttribute("scope", "col")
	tableErrors.AddHeader("Type").SetAttribute("scope", "col")
	tableErrors.AddHeader("Error").SetAttribute("scope", "col")
	tableErrors.Head.SetAttribute("scope", "row")
	a.em["div-table-errors"].SetElement(tableErrors.Element)
	for _, ee := range cloudtrail.ErrorEvents() {
		row := tableErrors.AddRow()
		link := bootstrap.NewLinkButton(ee.Name)
		json, _ := ee.JSONString("<br>", "&nbsp;&nbsp;")
		json = base64.StdEncoding.EncodeToString([]byte(json))
		link.SetAttribute("onclick", fmt.Sprintf("set_code('div-event','%v');", json))
		row.AddElement(bootstrap.NewElement("td", "", link))
		row.AddCells(ee.Type, ee.ErrorCode)
	}
	gowd.ExecJS("$('#table-errors').DataTable({'pageLength': 5});")
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
	log.SetOutput(a)
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	defer func() {
		a.em["button-loadevents"].UnsetClass("disabled")
		a.onFetchProgress(100, 100)
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

func (a *app) createDocLink(docid string) *gowd.Element {
	doc, err := a.indexer.Index.Document(docid)
	if err != nil {
		return gowd.NewText(fmt.Sprintf("%v", err))
	}
	text := ""
	for _, f := range doc.Fields {
		text += fmt.Sprintf("%v:%v; ", f.Name(), string(f.Value()))
		if len(text) > 100 {
			break
		}
	}
	link := bootstrap.NewLinkButton(text[:100])
	link.Object = fmt.Sprintf("%v - lala", doc.GoString())
	link.OnEvent(gowd.OnClick, a.errorLinkButtonClicked)
	return link
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
	err = a.addFromTemplate(div, "search-results.html")
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
	}

	summary := fmt.Sprintf("%d matches, showing %d through %d, took %s\n", sr.Total, sr.Request.From+1, sr.Request.From+len(sr.Hits), sr.Took)
	a.em["text-search-summary"].SetText(summary)
	divsr := a.em["div-sr"]

	for i, hit := range sr.Hits {
		link := a.createDocLink(hit.ID)
		header := bootstrap.NewElement("h4", "heading-small mb-4")
		header.AddElement(gowd.NewText(fmt.Sprintf("#%v", i)))
		header.AddHTML("&nbsp;", nil)
		header.AddElement(link)
		header.AddHTML("&nbsp;", nil)
		header.AddElement(gowd.NewStyledText(fmt.Sprintf("(%f)", hit.Score), gowd.ItalicText))
		dr := bootstrap.NewElement("div", "card-body", header)
		//link.OnEvent(gowd.OnClick, a.buttonSearchClicked)
		for fragmentField, fragments := range hit.Fragments {
			dr.AddElement(gowd.NewStyledText(fragmentField, gowd.StrongText))
			for _, fragment := range fragments {
				dr.AddHTML(fragment, nil)
			}
		}
		for otherFieldName, otherFieldValue := range hit.Fields {
			if _, ok := hit.Fragments[otherFieldName]; !ok {
				dr.AddElement(gowd.NewStyledText(otherFieldName, gowd.StrongText))
				dr.AddElement(gowd.NewText(fmt.Sprintf("%v", otherFieldValue)))
			}
		}
		divsr.AddElement(dr)
		divsr.AddElement(gowd.NewElement("hr"))

	}
	// if len(sr.Facets) > 0 {
	// 	html += fmt.Sprintf("Facets:\n")
	// 	for fn, f := range sr.Facets {
	// 		html += fmt.Sprintf("%s(%d)\n", fn, f.Total)
	// 		for _, t := range f.Terms {
	// 			hmtl += fmt.Sprintf("\t%s(%d)\n", t.Term, t.Count)
	// 		}
	// 		if f.Other != 0 {
	// 			html += fmt.Sprintf("\tOther(%d)\n", f.Other)
	// 		}
	// 	}
	// }
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
	a.body.Render()
}

//Write is used for displaying `log` messages
func (a *app) Write(p []byte) (n int, err error) {
	a.em["span_progress"].SetText(string(p))
	a.body.Render()
	return len(p), nil
}
