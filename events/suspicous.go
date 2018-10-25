package events

//SuspicousAssumeRole holds information about a suspicous AssumeRole usage
type SuspicousAssumeRole struct {
	ARN             string //ARN given
	ToUser          string //To user
	ToIP            string //To IP
	UsedByIP        string //(BUT...) Used by this IP
	UsedByUserAgent string //and this user agent
	UsedByUser      string // and this user
	UsedByEvent     Event  // the event itself
	AssumeRoleEvent Event  // The Assume role evnet
}

//Suspicous holds suspicous assume role events
var Suspicous []SuspicousAssumeRole

//AddSuspicious adds a suspcisous events
func AddSuspicious(sar SuspicousAssumeRole) {
	Suspicous = append(Suspicous, sar)
}
