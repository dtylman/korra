package assumerole

import (
	"github.com/dtylman/korra/analyzer/cloudtrail"
)

//SessionAnalyzer ...
type SessionAnalyzer struct {
}

//Analyze ...
func (sa *SessionAnalyzer) Analyze(e cloudtrail.Event) error {
	sess, ok := Sessions[e.UserIdentity.ARN]
	if ok {
		if !sess.HasSourceIP(e.SourceIPAddress) {
			sess.AddIssue("", "ARN '%v' used from an IP address '%v' but was never assigned to. User: '%v', User agent: '%v'",
				e.UserIdentity.ARN,
				e.SourceIPAddress,
				e.UserIdentity.UserName,
				e.UserAgent)
		}
	}
	return nil
}

//Name ...
func (sa *SessionAnalyzer) Name() string {
	return "AssumeRoleSessionAnalyzer"
}

// Clear ...
func (sa *SessionAnalyzer) Clear() error {
	return nil
}
