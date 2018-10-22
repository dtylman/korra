package main

import (
	"io/ioutil"
	"log"
	"strings"

	"github.com/dtylman/gowd"
	"github.com/dtylman/gowd/bootstrap"
)

var body *gowd.Element

func run() error {
	data, err := ioutil.ReadFile("content.html")
	if err != nil {
		return err
	}

	elements, err := gowd.ParseElements(strings.NewReader(string(data)), nil)
	if err != nil {
		return err
	}
	body := bootstrap.NewContainer(true)
	for _, elem := range elements {
		body.AddElement(elem)
	}
	if err != nil {
		return err
	}
	gowd.ExecJS(`$('#example').DataTable({
		"oLanguage": {
		  "oPaginate": {
			"sNext": ">>",
			"sPrevious": "<<",
		  }
		}
	  });`)
	//start the ui loop
	return gowd.Run(body)
}
func main() {
	err := run()
	if err != nil {
		log.Println(err)
	}
}
