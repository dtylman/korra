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
	body      *gowd.Element
	em        gowd.ElementsMap
	content   *gowd.Element
	logCard   *gowd.Element
	formCard  *gowd.Element
	tableCard *gowd.Element
}

func newApp() (*app, error) {
	a := new(app)
	a.em = gowd.NewElementMap()
	a.body = bootstrap.NewContainer(true)
	var err error
	a.logCard, err = a.loadFromTemplate("log.html")
	if err != nil {
		return nil, err
	}
	a.formCard, err = a.loadFromTemplate("form.html")
	err = a.addFromTemplate(a.body, "body.html")
	if err != nil {
		return nil, err
	}
	a.tableCard, err = a.loadFromTemplate("table.html")
	if err != nil {
		return nil, err
	}
	a.content = a.em["main-content"]
	a.setContent(a.formCard)
	a.em["btn-start"].OnEvent(gowd.OnClick, a.btnStartClicked)

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

func (a *app) btnStartClicked(sender *gowd.Element, event *gowd.EventElement) {
	sender.SetClass("disabled")
	awsclient.Options.Region = a.em["input-region"].GetValue()
	events.Options.VerboseAssumeRoleEvents = false
	var err error
	awsclient.Options.MaxOnlineEvents, err = strconv.Atoi(a.em["input-maxevents"].GetValue())
	if err != nil {
		gowd.Alert(fmt.Sprintf("%v", err))
		return
	}
	a.em["samp-log"].RemoveElements()
	a.content.RemoveElement(a.logCard)
	a.content.AddElement(a.logCard)
	go func() {
		a.em["btn-stop"].UnsetClass("disabled")
		log.SetOutput(a)
		defer func() {
			sender.UnsetClass("disabled")
			a.em["btn-stop"].SetClass("disabled")
			a.body.Render()
		}()
		err := awsclient.Analayze()
		if err != nil {
			gowd.Alert(fmt.Sprintf("%v", err))
			return
		}
		if len(events.Records) == 0 {
			log.Println("No assume roles events found")
		} else {
			a.content.AddElement(a.tableCard)
			tbody := a.em["tbody-assume-role"]
			for _, are := range events.Records {
				tr := bootstrap.NewTableRow()
				tr.AddCells(are.AssumedRoleARN, fmt.Sprintf("%v", are.IPs), fmt.Sprintf("%v", are.Time), are.Session)
				tbody.AddElement(tr.Element)
			}
			gowd.ExecJS(`$('#table-assume-role').DataTable({
				"oLanguage": {
				  "oPaginate": {
					"sNext": ">>",
					"sPrevious": "<<",
				  }
				}
				});`)
		}
	}()

}

func (a *app) Write(p []byte) (n int, err error) {
	samplog := a.em["samp-log"]
	samplog.AddHTML(string(p), nil)
	samplog.AddHTML("<br>", nil)
	gowd.ExecJS(`window.scrollTo(0,document.body.scrollHeight);`)
	a.body.Render()
	return len(p), nil
}
