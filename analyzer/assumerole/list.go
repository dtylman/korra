package assumerole

import (
	"fmt"

	"github.com/dtylman/korra/analyzer/cloudtrail"
)

//Sessions holds a map off assume roles by arn
var Sessions map[string]Session

//AddEvent adds an event to the sessions
func AddEvent(e cloudtrail.Event) error {
	if e.Name != "AssumeRole" {
		return nil
	}
	if e.HasError() {
		return nil
	}
	if e.Name == "AssumeRole" {
		arn := e.BuildAssumedRoleARN()
		if arn == "" {
			return fmt.Errorf("Cannot get AssumeRoleARN for event: %v", e)
		}
		sess, ok := Sessions[arn]
		if ok {
			sess.AddEvent(e)
			Sessions[arn] = sess
		} else {
			sess = Session{
				Name:           e.RequestParameters.RoleSessionName,
				AssumedRoleARN: arn,
			}
			sess.AddEvent(e)
			Sessions[arn] = sess
		}
	}
	return nil
}

//Clear resets the sessions lists
func Clear() {
	Sessions = make(map[string]Session)
}
