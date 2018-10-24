package events

import (
	"log"
	"sort"
	"time"
)

//AssumeRoleSession represents  AssumeRoleSession
type AssumeRoleSession struct {
	Session        string
	AssumedRoleARN string
	IPs            map[string]bool
	Time           time.Time
	Raw            map[string]string
}

//Sessions holds a map off assume roles by arn
var Sessions map[string]AssumeRoleSession

//ErrorEvents are events with errors
var ErrorEvents []Event

//Analyze analyses the events
func Analyze() error {
	assumeRoleEvents := 0
	compromisedEvents := 0
	Sessions = make(map[string]AssumeRoleSession)
	ErrorEvents = make([]Event, 0)

	log.Printf("Analyzing %v events...", len(events))
	sort.Sort(ByTime(events))
	for _, e := range events {
		if e.HasError() {
			ErrorEvents = append(ErrorEvents, e)
			continue
		}
		if e.Name == "AssumeRole" {
			estr, _ := e.JSONString()
			assumeRoleEvents++
			arn := e.BuildAssumedRoleARN()
			if arn == "" {
				log.Println(e.JSONString())
			}
			r, ok := Sessions[arn]
			if ok {
				r.IPs[e.SourceIPAddress] = true
				r.Time = e.Time
				r.Raw[e.SourceIPAddress] = estr
				Sessions[arn] = r
			} else {
				Sessions[arn] = AssumeRoleSession{
					Session:        e.RequestParameters.RoleSessionName,
					AssumedRoleARN: e.BuildAssumedRoleARN(),
					IPs:            map[string]bool{e.SourceIPAddress: true},
					Time:           e.Time,
					Raw:            map[string]string{e.SourceIPAddress: estr},
				}
			}
		}
		r, ok := Sessions[e.UserIdentity.ARN]
		if ok {
			_, ok = r.IPs[e.SourceIPAddress]
			if !ok {
				log.Printf("%v given to %v used from '%v' User: '%v' User Agent: '%v'", r.AssumedRoleARN, r.IPs,
					e.SourceIPAddress, e.UserIdentity.UserName, e.UserAgent)
				compromisedEvents++
			}
		}
	}
	log.Printf("Analyzed %v events, Skipped %v with error codes, found %v AssumeRole Session, %v suspicious", len(events), len(ErrorEvents), assumeRoleEvents, compromisedEvents)
	return nil
}
