package cloudtrail

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sort"
)

//Events holds the list of loaded events
var Events []Event

//Clear resets the list of loaded events
func Clear() {
	Events = make([]Event, 0)
}

//AddEvent adds one event
func AddEvent(event Event) {
	Events = append(Events, event)
}

//Sort sorts events by time
func Sort() {
	sort.Sort(ByTime(Events))
}

//ErrorEvents returns a list of events with errors
func ErrorEvents() []Event {
	list := make([]Event, 0)
	for _, e := range Events {
		if e.HasError() {
			list = append(list, e)
		}
	}
	return list
}

const eventsFilename = "korra.events.json"

//LoadFromFile loads events from file
func LoadFromFile() error {
	_, err := os.Stat(eventsFilename)
	if os.IsNotExist(err) {
		return nil
	}
	data, err := ioutil.ReadFile(eventsFilename)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &Events)
}

//SaveToFile persists all events to a local file
func SaveToFile() error {
	data, err := json.Marshal(Events)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(eventsFilename, data, 0644)
}
