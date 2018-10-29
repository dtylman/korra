package analyzer

import (
	"encoding/json"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/dtylman/korra/analyzer/assumerole"
	cloudtrailevents "github.com/dtylman/korra/analyzer/cloudtrail"
)

//Options global options
var Options struct {
	//AccessKey AWS access key
	AccessKey string
	//Secret AWS secret
	Secret string
	//SessionToken AWS session token
	SessionToken string
	//Region os AWS region
	Region string
	//MaxOnlineEvents is the maximal number of events to load from cloudtrail
	MaxOnlineEvents int
}

//TotalRead total number of events read
var TotalRead int

//ProgressFunc defines a function for progress indication
type ProgressFunc func(value int, total int)

//Analyzer something that analyzes events
type Analyzer interface {
	Analyze(event cloudtrailevents.Event) error
	Name() string
}

//Analyzers list of analyzers
var Analyzers []Analyzer

//Reset resets analyzer
func Reset() {
	cloudtrailevents.Reset()
	assumerole.Reset()
}

//NewSession creates new AWS session
func NewSession() (*session.Session, error) {
	log.Println("Creating AWS session...")
	conf := &aws.Config{
		Region: aws.String(Options.Region),
	}

	if Options.AccessKey != "" {
		conf.Credentials = credentials.NewStaticCredentials(Options.AccessKey, Options.Secret, Options.SessionToken)
	}

	return session.NewSession(conf)
}

// reads all events from cloudtrail and builds assumerole sessions
func populate(progress ProgressFunc) error {
	Reset()
	sess, err := NewSession()
	if err != nil {
		return err
	}
	svc := cloudtrail.New(sess)

	input := &cloudtrail.LookupEventsInput{
		MaxResults: aws.Int64(50),
		EndTime:    aws.Time(time.Now())}

	needMore := true
	TotalRead = 0
	if progress != nil {
		progress(TotalRead, Options.MaxOnlineEvents)
		defer progress(TotalRead, TotalRead)
	}
	for needMore {
		resp, err := svc.LookupEvents(input)
		if err != nil {
			return err
		}
		input.NextToken = resp.NextToken
		if aws.StringValue(resp.NextToken) == "" {
			needMore = false
			continue
		}
		for _, object := range resp.Events {
			TotalRead++
			if TotalRead >= Options.MaxOnlineEvents {
				needMore = false
				continue
			}
			raw := aws.StringValue(object.CloudTrailEvent)
			var event cloudtrailevents.Event
			err := json.Unmarshal([]byte(raw), &event)
			if err != nil {
				log.Println(err)
			} else {
				cloudtrailevents.AddEvent(event)
			}
		}
		log.Printf("Read %v events", TotalRead)
		if progress != nil {
			progress(TotalRead, Options.MaxOnlineEvents)
		}
	}

	cloudtrailevents.Sort()
	// build assume role sessions
	for _, e := range cloudtrailevents.Events {
		err := assumerole.AddEvent(e)
		if err != nil {
			log.Println(err)
		}
	}
	return nil
}

//LoadAndAnalyze resets analyzer, loads new data and perform all analysis
func LoadAndAnalyze(progress ProgressFunc) error {
	err := populate(progress)
	if err != nil {
		return err
	}
	for _, e := range cloudtrailevents.Events {
		for _, a := range Analyzers {
			err = a.Analyze(e)
			if err != nil {
				log.Printf("%v: %v", a.Name(), err)
			}
		}
	}
	return nil
}
