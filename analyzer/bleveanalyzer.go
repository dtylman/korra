package analyzer

import (
	"errors"
	"os"

	"github.com/blevesearch/bleve"
	"github.com/dtylman/korra/analyzer/cloudtrail"
)

//BleveAnalyzer ...
type BleveAnalyzer struct {
	Index bleve.Index
}

//NewBleveAnalyzer ...
func NewBleveAnalyzer(path string) (*BleveAnalyzer, error) {
	if path == "" || path == "/" {
		return nil, errors.New("Path is empty, will refuse to remove everything")
	}
	err := os.RemoveAll(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ba := new(BleveAnalyzer)
	ba.Index, err = bleve.New(path, bleve.NewIndexMapping())
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
