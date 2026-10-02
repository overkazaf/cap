package importer

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/overkazaf/cap/internal/types"
)

// charlesSession mirrors a Charles Proxy "Save Session As... XML" export: a
// flat list of transactions, each one request/response pair. The XMLName
// field asserts the root element so a differently-shaped XML document (e.g.
// a HAR file fed to the wrong importer) fails fast with a clear error.
type charlesSession struct {
	XMLName      xml.Name             `xml:"charles-session"`
	Transactions []charlesTransaction `xml:"transaction"`
}

type charlesTransaction struct {
	Request  charlesRequest  `xml:"request"`
	Response charlesResponse `xml:"response"`
	Duration int64           `xml:"duration"` // ms
}

type charlesRequest struct {
	Method  string   `xml:"method,attr"`
	URL     string   `xml:"url,attr"`
	Headers []header `xml:"header"`
	Body    string   `xml:"body"`
}

type charlesResponse struct {
	Status  int      `xml:"status,attr"`
	Headers []header `xml:"header"`
	Body    string   `xml:"body"`
}

// ImportCharles parses a Charles Proxy XML session export into cap's Flow
// type. Each <transaction> becomes one Flow, in document order.
func ImportCharles(r io.Reader) ([]*types.Flow, error) {
	var doc charlesSession
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("importer: decode Charles session: %w", err)
	}

	flows := make([]*types.Flow, 0, len(doc.Transactions))
	for i, tx := range doc.Transactions {
		flows = append(flows, tx.toFlow(i+1))
	}
	return flows, nil
}

// toFlow converts one Charles transaction into a Flow. seq is its 1-based
// position in the document, used to generate the "imp-N" ID.
func (tx charlesTransaction) toFlow(seq int) *types.Flow {
	flow := &types.Flow{
		ID:          fmt.Sprintf("imp-%d", seq),
		Method:      tx.Request.Method,
		URL:         tx.Request.URL,
		ReqHeaders:  headerMap(tx.Request.Headers),
		Status:      tx.Response.Status,
		RespHeaders: headerMap(tx.Response.Headers),
		LatencyMs:   tx.Duration,
	}

	flow.Host, flow.Path = hostAndPath(tx.Request.URL)
	if flow.Host == "" {
		flow.Host = headerValue(tx.Request.Headers, "Host")
	}

	if tx.Request.Body != "" {
		flow.ReqBody = []byte(tx.Request.Body)
	}
	if tx.Response.Body != "" {
		flow.RespBody = []byte(tx.Response.Body)
	}

	return flow
}
