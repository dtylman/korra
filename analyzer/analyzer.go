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

//ProgressFunc defines a function for progress indication
type ProgressFunc func(value int, total int)

//Analyzer something that analyzes events
type Analyzer interface {
	Analyze(event cloudtrailevents.Event) error
	Name() string
}

//Analyzers list of analyzers
var Analyzers []Analyzer

//Clear resets analyzer
func Clear() {
	cloudtrailevents.Clear()
	assumerole.Clear()
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

//Load reads all events from cloudtrail and builds assumerole sessions
func Load(progress ProgressFunc) error {
	Clear()
	sess, err := NewSession()
	if err != nil {
		return err
	}
	svc := cloudtrail.New(sess)

	input := &cloudtrail.LookupEventsInput{
		MaxResults: aws.Int64(50),
		EndTime:    aws.Time(time.Now())}

	needMore := true
	total := len(cloudtrailevents.Events)
	if progress != nil {
		progress(total, Options.MaxOnlineEvents)
		defer progress(total, total)
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
			total = len(cloudtrailevents.Events)
			if total >= Options.MaxOnlineEvents {
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
		log.Printf("Read %v events", total)
		if progress != nil {
			progress(total, Options.MaxOnlineEvents)
		}
	}
	return nil
}

//Analyze runs analyzers on data
func Analyze() error {
	assumerole.Clear()

	cloudtrailevents.Sort()
	// build assume role sessions
	for _, e := range cloudtrailevents.Events {
		err := assumerole.AddEvent(e)
		if err != nil {
			log.Println(err)
		}
	}
	for _, e := range cloudtrailevents.Events {
		for _, a := range Analyzers {
			err := a.Analyze(e)
			if err != nil {
				log.Printf("%v: %v", a.Name(), err)
			}
		}
	}
	return nil
}

//LoadAndAnalyze resets analyzer, loads new data and perform all analysis
func LoadAndAnalyze(progress ProgressFunc) error {
	err := Load(progress)
	if err != nil {
		return err
	}
	return Analyze()
}
