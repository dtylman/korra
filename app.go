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
	a.setContent(a.fetchCard)
	return a, nil
}

func (a *app) setContent(content *gowd.Element) {
	a.content.RemoveElements()
	a.content.AddElement(content)
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

func (a *app) showModal(sender *gowd.Element, event *gowd.EventElement) {
	err := a.addFromTemplate(a.body, "modal.html")
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
	}
	gowd.ExecJS(`$('#modal-notification').modal('show');`)
}

func (a *app) menuButttonAnalyzeClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.em["span-total-read"].SetText(fmt.Sprintf("%v", awsclient.TotalRead))
	a.em["span-assume-role-session"].SetText(fmt.Sprintf("%v", len(events.Sessions)))
	a.em["button-errros"].SetText(fmt.Sprintf("%v", len(events.ErrorEvents)))
	tbodyErrors := a.em["tbody_errors"]
	for _, ee := range events.ErrorEvents {
		row := bootstrap.NewTableRow()
		cell := gowd.NewElement("td")
		link := bootstrap.NewLinkButton(ee.Name)
		link.OnEvent(gowd.OnClick, a.showModal)
		cell.AddElement(link)
		row.AddElement(cell)
		row.AddCells(ee.Type, ee.ErrorCode)
		tbodyErrors.AddElement(row.Element)
	}

	a.setContent(a.analyzeCard)
}

func (a *app) menuButttonFetchClicked(sender *gowd.Element, event *gowd.EventElement) {
	a.setContent(a.fetchCard)
}

func (a *app) buttonLoadEventsClicked(sender *gowd.Element, event *gowd.EventElement) {
	sender.SetClass("disabled")
	awsclient.Options.Region = a.em["input-region"].GetValue()
	var err error
	awsclient.Options.MaxOnlineEvents, err = strconv.Atoi(a.em["input-maxevents"].GetValue())
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
		return
	}
	go func() {
		a.em["button-loadevents-stop"].UnsetClass("disabled")
		log.SetOutput(a)
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
		defer func() {
			sender.UnsetClass("disabled")
			a.em["button-loadevents-stop"].SetClass("disabled")
			a.body.Render()
		}()
		err := awsclient.Analayze(a.fetchProgress)
		if err != nil {
			gowd.Alert(fmt.Sprintf("%v", err))
			return
		}
		if len(events.Sessions) == 0 {
			log.Println("No assume roles events found")
		} else {
			// a.content.AddElement(a.tableCard)
			// tbody := a.em["tbody-assume-role"]
			// for _, are := range events.Records {
			// 	tr := bootstrap.NewTableRow()
			// 	tr.AddCells(are.AssumedRoleARN, fmt.Sprintf("%v", are.IPs), fmt.Sprintf("%v", are.Time), are.Session)
			// 	tbody.AddElement(tr.Element)
			// }
		}
	}()

}

func (a *app) fetchProgress(value int, total int) {
	var percent int
	if total == 0 {
		percent = 0
	} else {
		percent = 100 * value / total
	}
	a.em["span_progress_percentage"].SetText(fmt.Sprintf("%v%%", percent))
	a.em["progress-bar-fetch"].SetAttribute("style", fmt.Sprintf("width: %v%%;", percent))
}

func (a *app) Write(p []byte) (n int, err error) {
	a.em["span_progress"].SetText(string(p))
	a.body.Render()
	return len(p), nil
}
