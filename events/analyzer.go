package events

import (
	"log"
	"sort"
)

//Reset resets analyzer
func Reset() {
	Sessions = make(map[string]AssumeRoleSession)
	LoadedEvents = make([]Event, 0)
	ErrorEvents = make([]Event, 0)
	Suspicous = make([]SuspicousAssumeRole, 0)
}

//Analyze analyses the events
func Analyze() error {
	log.Printf("Analyzing %v events...", len(LoadedEvents))
	sort.Sort(ByTime(LoadedEvents))
	for _, e := range LoadedEvents {
		if e.HasError() {
			AddErrorEvent(e)
			continue
		}
		if e.Name == "AssumeRole" {
			arn := e.BuildAssumedRoleARN()
			if arn == "" {
				e.ErrorCode = "Korra: Cannot get AssumeRoleARN for message"
				AddErrorEvent(e)
				continue
			}
			sess, ok := Sessions[arn]
			if ok {
				sess.AddEvent(e)
				Sessions[arn] = sess
			} else {
				Sessions[arn] = AssumeRoleSession{
					Session:        e.RequestParameters.RoleSessionName,
					AssumedRoleARN: arn,
				}
			}
		}
		//else?
		sess, ok := Sessions[e.UserIdentity.ARN]
		if ok {
			if !sess.HasSourceIP(e.SourceIPAddress) {
				sar := SuspicousAssumeRole{
					ARN:             sess.AssumedRoleARN,
					ToUser:          sess.Users(),
					ToIP:            sess.IPs(),
					UsedByIP:        e.SourceIPAddress,
					UsedByUserAgent: e.UserAgent,
					UsedByUser:      e.UserIdentity.UserName,
					UsedByEvent:     e,
					AssumeRoleEvent: sess.Events[0],
				}
				AddSuspicious(sar)
			}
		}
	}
	log.Printf("Analyzed %v events", len(LoadedEvents))
	return nil
}
