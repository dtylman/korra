package cloudtrail

import "sort"

//Events holds the list of loaded events
var Events []Event

//Reset resets the list of loaded events
func Reset() {
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
