package events

import (
	"log"
	"sort"
	"time"
)

// Options defines analyzer global options
var Options struct {
	// VerboseAssumeRoleEvents if true, will log AssumeRoleEvents when are processed
	VerboseAssumeRoleEvents bool
}

//AssumeRole represents AssumeRole AssumeRole
type AssumeRole struct {
	Session        string
	AssumedRoleARN string
	IPs            map[string]bool
	Time           time.Time
	Raw            map[string]string
}

//Records holds a map off assume roles by arn
var Records map[string]AssumeRole

//Analyze analyses the events
func Analyze() error {
	assumeRoleEvents := 0
	compromisedEvents := 0
	skipped := 0
	Records = make(map[string]AssumeRole)

	log.Printf("Analyzing %v events...", len(events))
	sort.Sort(ByTime(events))
	for _, e := range events {
		if e.HasError() {
			skipped++
			continue
		}
		if e.Name == "AssumeRole" {
			estr, _ := e.JSONString()
			if Options.VerboseAssumeRoleEvents {
				log.Println(estr)
			}
			assumeRoleEvents++
			arn := e.BuildAssumedRoleARN()
			if arn == "" {
				log.Println(e.JSONString())
			}
			r, ok := Records[arn]
			if ok {
				r.IPs[e.SourceIPAddress] = true
				r.Time = e.Time
				r.Raw[e.SourceIPAddress] = estr
				Records[arn] = r
			} else {
				Records[arn] = AssumeRole{
					Session:        e.RequestParameters.RoleSessionName,
					AssumedRoleARN: e.BuildAssumedRoleARN(),
					IPs:            map[string]bool{e.SourceIPAddress: true},
					Time:           e.Time,
					Raw:            map[string]string{e.SourceIPAddress: estr},
				}
			}
		}
		r, ok := Records[e.UserIdentity.ARN]
		if ok {
			_, ok = r.IPs[e.SourceIPAddress]
			if !ok {
				log.Printf("%v given to %v used from '%v' User: '%v' User Agent: '%v'", r.AssumedRoleARN, r.IPs,
					e.SourceIPAddress, e.UserIdentity.UserName, e.UserAgent)
				compromisedEvents++
			}
		}
	}
	log.Printf("Analyzed %v events, Skipped %v with error codes, found %v 'AssumeRole', %v suspicious", len(events), skipped, assumeRoleEvents, compromisedEvents)
	return nil
}
