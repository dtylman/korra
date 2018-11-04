package analyzer

import (
	"os"

	"github.com/blevesearch/bleve"
	"github.com/dtylman/korra/analyzer/cloudtrail"
)

//BleveAnalyzer ...
type BleveAnalyzer struct {
	Index bleve.Index
	path  string
}

//NewBleveAnalyzer ...
func NewBleveAnalyzer(path string) (*BleveAnalyzer, error) {
	ba := new(BleveAnalyzer)
	ba.path = path
	_, err := os.Stat(ba.path)
	if err == nil {
		ba.Index, err = bleve.Open(ba.path)
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		ba.Index, err = bleve.New(path, bleve.NewIndexMapping())
	}
	if err != nil {
		return nil, err
	}
	return ba, nil
}

//Analyze ...
func (ba *BleveAnalyzer) Analyze(e cloudtrail.Event) error {
	return ba.Index.Index(e.ID, e)
}

// Close ...
func (ba *BleveAnalyzer) Close() error {
	return ba.Index.Close()
}

//Name ...
func (ba *BleveAnalyzer) Name() string {
	return "BleveAnalyzer"
}

//Clear ...
func (ba *BleveAnalyzer) Clear() error {
	var err error
	ba.Index, err = bleve.New(ba.path, bleve.NewIndexMapping())
	return err
}
