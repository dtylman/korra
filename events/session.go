package events

//AssumeRoleSession represents  AssumeRoleSession
type AssumeRoleSession struct {
	Session        string
	AssumedRoleARN string
	Events         []Event
}

//Sessions holds a map off assume roles by arn
var Sessions map[string]AssumeRoleSession

//AddEvent adds event to session
func (ars *AssumeRoleSession) AddEvent(e Event) {
	if len(ars.Events) == 0 {
		ars.Events = make([]Event, 0)
	}
	ars.Events = append(ars.Events, e)
}

//HasSourceIP returns true if session has the given ip address
func (ars *AssumeRoleSession) HasSourceIP(ip string) bool {
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
func (ars *AssumeRoleSession) Users() string {
	var users map[string]bool
	for _, e := range ars.Events {
		users[e.UserIdentity.UserName] = true
	}
	return keysToStr(users)
}

//IPs returns all source IP address associated with this session
func (ars *AssumeRoleSession) IPs() string {
	var ips map[string]bool
	for _, e := range ars.Events {
		ips[e.SourceIPAddress] = true
	}
	return keysToStr(ips)
}
