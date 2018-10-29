package analyzer

import (
	"github.com/dtylman/korra/analyzer/assumerole"
	"github.com/dtylman/korra/analyzer/cloudtrail"
)

type assumeRoleSessionAnalyzer struct {
}

func (ars *assumeRoleSessionAnalyzer) Analyze(e *cloudtrail.Event) error {
	sess, ok := assumerole.Sessions[e.UserIdentity.ARN]
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
