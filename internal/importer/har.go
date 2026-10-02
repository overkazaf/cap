package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

// harDocument mirrors the parts of the HAR 1.2 format cap understands: a log
// holding a flat list of request/response entries. Fields outside this
// shape (pages, cache info, the detailed timings breakdown, etc.) are
// ignored rather than rejected.
type harDocument struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

// harEntry is one captured request/response pair.
type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"` // total round-trip time, ms
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
}

// harPayload is the shape shared by request.postData and response.content.
type harPayload struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harRequest struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Headers  []header    `json:"headers"`
	PostData *harPayload `json:"postData"`
}

type harResponse struct {
	Status  int         `json:"status"`
	Headers []header    `json:"headers"`
	Content *harPayload `json:"content"`
}

// ImportHAR parses a HAR (HTTP Archive) capture into cap's Flow type. Each
// log.entries[] element becomes one Flow, in order.
func ImportHAR(r io.Reader) ([]*types.Flow, error) {
	var doc harDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("importer: decode HAR: %w", err)
	}

	flows := make([]*types.Flow, 0, len(doc.Log.Entries))
	for i, e := range doc.Log.Entries {
		flows = append(flows, e.toFlow(i+1))
	}
	return flows, nil
}

// toFlow converts one HAR entry into a Flow. seq is its 1-based position in
// the document, used to generate the "imp-N" ID.
func (e harEntry) toFlow(seq int) *types.Flow {
	flow := &types.Flow{
		ID:          fmt.Sprintf("imp-%d", seq),
		Method:      e.Request.Method,
		URL:         e.Request.URL,
		ReqHeaders:  headerMap(e.Request.Headers),
		Status:      e.Response.Status,
		RespHeaders: headerMap(e.Response.Headers),
		LatencyMs:   int64(math.Round(e.Time)),
	}

	flow.Host, flow.Path = hostAndPath(e.Request.URL)
	if flow.Host == "" {
		flow.Host = headerValue(e.Request.Headers, "Host")
	}

	if e.Request.PostData != nil {
		flow.ReqBody = []byte(e.Request.PostData.Text)
		flow.ReqBodyType = e.Request.PostData.MimeType
	}
	if e.Response.Content != nil {
		flow.RespBody = []byte(e.Response.Content.Text)
		flow.RespBodyType = e.Response.Content.MimeType
	}
	if e.StartedDateTime != "" {
		if ts, err := time.Parse(time.RFC3339, e.StartedDateTime); err == nil {
			flow.Timestamp = ts
		}
	}

	return flow
}
