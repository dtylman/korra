package assumerole

import (
	"fmt"

	"github.com/dtylman/korra/analyzer/cloudtrail"
)

//Session represents  Session
type Session struct {
	Name           string
	AssumedRoleARN string
	Events         []cloudtrail.Event
	Issues         []string
}

//AddEvent adds event to session
func (ars *Session) AddEvent(e cloudtrail.Event) {
	if len(ars.Events) == 0 {
		ars.Events = make([]cloudtrail.Event, 0)
	}
	ars.Events = append(ars.Events, e)
}

//HasSourceIP returns true if session has the given ip address
func (ars *Session) HasSourceIP(ip string) bool {
	for _, e := range ars.Events {
		if e.SourceIPAddress == ip {
			return true
		}
	}
	return false
}

func keysToStr(m map[string]bool) string {
	var str string
	for k := range m {
		str += k + " "
	}
	return str
}

//Users returns all users associated with this session
func (ars *Session) Users() string {
	var users map[string]bool
	for _, e := range ars.Events {
		users[e.UserIdentity.UserName] = true
	}
	return keysToStr(users)
}

//IPs returns all source IP address associated with this session
func (ars *Session) IPs() string {
	var ips map[string]bool
	for _, e := range ars.Events {
		ips[e.SourceIPAddress] = true
	}
	return keysToStr(ips)
}

//AddIssue adds analyzed issue to the session
func (ars *Session) AddIssue(severity string, message string, args ...interface{}) {
	if len(ars.Issues) == 0 {
		ars.Issues = make([]string, 0)
	}
	msg := fmt.Sprintf("%v: %v", severity, fmt.Sprintf(message, args...))
	ars.Issues = append(ars.Issues, msg)
}
