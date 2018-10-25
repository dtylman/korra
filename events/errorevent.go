package events

//ErrorEvents are events with errors
var ErrorEvents []Event

//AddErrorEvent adds an error event to list
func AddErrorEvent(e Event) {
	ErrorEvents = append(ErrorEvents, e)
}
