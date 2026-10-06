package wailsgui

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/overkazaf/cap/internal/compare"
	"github.com/overkazaf/cap/internal/export/agent"
	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/grouping"
	"github.com/overkazaf/cap/internal/importer"
	"github.com/overkazaf/cap/internal/proto"
	"github.com/overkazaf/cap/internal/replay"
	"github.com/overkazaf/cap/internal/sequence"
	"github.com/overkazaf/cap/internal/sign"
	"github.com/overkazaf/cap/internal/stats"
	"github.com/overkazaf/cap/internal/types"
)

// ==================== Flows ====================

type FlowSummary struct {
	ID       string `json:"id"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Latency  int64  `json:"latency_ms"`
	BodyType string `json:"body_type"`
	Time     string `json:"time"`
}

type FlowDetail struct {
	FlowSummary
	ReqHeaders  map[string]string `json:"req_headers"`
	ReqBody     string            `json:"req_body"`
	RespHeaders map[string]string `json:"resp_headers"`
	RespBody    string            `json:"resp_body"`
	Tags        []string          `json:"tags"`
	SignParams  []string          `json:"sign_params"`
	SourceRef   *types.SourceRef  `json:"source_ref"`
}

func (a *App) GetFlows(host, method, search string, limit int) []FlowSummary {
	if limit <= 0 {
		limit = 10000
	}
	flows, _ := a.store.ListFlows(types.FlowFilter{
		Host: host, Method: method, Search: search, Limit: limit,
	})
	result := make([]FlowSummary, len(flows))
	for i, f := range flows {
		result[i] = FlowSummary{
			ID:       f.ID,
			Method:   f.Method,
			URL:      f.URL,
			Host:     f.Host,
			Path:     f.Path,
			Status:   f.Status,
			Latency:  f.LatencyMs,
			BodyType: f.RespBodyType,
			Time:     f.Timestamp.Format("15:04:05.000"),
		}
	}
	return result
}

func (a *App) GetFlowDetail(id string) (*FlowDetail, error) {
	f, err := a.store.GetFlow(id)
	if err != nil {
		return nil, err
	}
	detail := &FlowDetail{
		FlowSummary: FlowSummary{
			ID:       f.ID,
			Method:   f.Method,
			URL:      f.URL,
			Host:     f.Host,
			Path:     f.Path,
			Status:   f.Status,
			Latency:  f.LatencyMs,
			BodyType: f.RespBodyType,
			Time:     f.Timestamp.Format("15:04:05.000"),
		},
		ReqHeaders:  f.ReqHeaders,
		ReqBody:     string(f.ReqBody),
		RespHeaders: f.RespHeaders,
		RespBody:    string(f.RespBody),
		Tags:        f.Tags,
		SignParams:  f.SignParams,
		SourceRef:   f.SourceRef,
	}

	if len(detail.SignParams) == 0 {
		detected := agent.DetectSignParams(f)
		if len(detected) > 0 {
			detail.SignParams = detected
		}
	}

	return detail, nil
}

func (a *App) ClearFlows() error {
	flows, _ := a.store.ListFlows(types.FlowFilter{Limit: 10000})
	for _, f := range flows {
		a.store.DeleteFlow(f.ID)
	}
	a.mu.Lock()
	a.flows = nil
	a.mu.Unlock()
	return nil
}

func (a *App) GetBodyHex(flowID string, isReq bool) (string, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return "", err
	}
	body := f.RespBody
	if isReq {
		body = f.ReqBody
	}
	if len(body) == 0 {
		return "(empty)", nil
	}
	return hex.EncodeToString(body), nil
}

// ==================== Export ====================

func (a *App) ExportCode(flowID, lang string) (string, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return "", err
	}
	return codegen.Generate(f, lang)
}

func (a *App) ExportAgent() (string, error) {
	flows, _ := a.store.ListFlows(types.FlowFilter{Limit: 500})
	out, err := agent.Format(flows, agent.FormatOptions{})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (a *App) GetLanguages() []string {
	return codegen.Languages()
}

// ==================== Replay ====================

type ReplayResult struct {
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Latency     int64             `json:"latency_ms"`
	StatusDiff  string            `json:"status_diff"`
	LatencyDiff int64             `json:"latency_diff"`
}

func (a *App) ReplayFlow(flowID string) (*ReplayResult, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}
	result, err := replay.Replay(f, replay.Options{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	rr := &ReplayResult{
		Status:  result.Replayed.Status,
		Headers: result.Replayed.RespHeaders,
		Body:    string(result.Replayed.RespBody),
		Latency: result.Replayed.LatencyMs,
	}
	if result.Diff != nil {
		rr.StatusDiff = result.Diff.StatusDiff
		rr.LatencyDiff = result.Diff.LatencyDiff
	}
	return rr, nil
}

type ModifyRequest struct {
	FlowID     string            `json:"flow_id"`
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	SetHeaders map[string]string `json:"set_headers"`
	DelHeaders []string          `json:"del_headers"`
	Body       string            `json:"body"`
}

func (a *App) ReplayModified(req ModifyRequest) (*ReplayResult, error) {
	f, err := a.store.GetFlow(req.FlowID)
	if err != nil {
		return nil, err
	}
	mods := replay.Modifications{
		URL:        req.URL,
		Method:     req.Method,
		SetHeaders: req.SetHeaders,
		DelHeaders: req.DelHeaders,
	}
	if req.Body != "" {
		mods.Body = []byte(req.Body)
	}
	result, err := replay.ReplayModified(f, mods, replay.Options{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	rr := &ReplayResult{
		Status:  result.Replayed.Status,
		Headers: result.Replayed.RespHeaders,
		Body:    string(result.Replayed.RespBody),
		Latency: result.Replayed.LatencyMs,
	}
	if result.Diff != nil {
		rr.StatusDiff = result.Diff.StatusDiff
		rr.LatencyDiff = result.Diff.LatencyDiff
	}
	return rr, nil
}

// ==================== Sign Analysis ====================

type SignResult struct {
	ParamName    string   `json:"param_name"`
	Value        string   `json:"value"`
	Encoding     string   `json:"encoding"`
	PossibleAlgs []string `json:"possible_algs"`
	InputGuess   string   `json:"input_guess"`
	Confidence   float64  `json:"confidence"`
}

func (a *App) AnalyzeSign(flowID string) ([]SignResult, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}
	analyses := sign.AnalyzeSingle(f)
	result := make([]SignResult, len(analyses))
	for i, an := range analyses {
		result[i] = SignResult{
			ParamName:    an.ParamName,
			Value:        an.Value,
			Encoding:     an.Encoding,
			PossibleAlgs: an.PossibleAlgs,
			InputGuess:   an.InputGuess,
			Confidence:   an.Confidence,
		}
	}
	return result, nil
}

// ==================== Protobuf ====================

func (a *App) DecodeProtobuf(flowID string, isReq bool) (string, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return "", err
	}
	body := f.RespBody
	if isReq {
		body = f.ReqBody
	}
	if len(body) == 0 {
		return "(empty)", nil
	}
	if !proto.IsProtobuf(body) {
		return "(not protobuf data)", nil
	}
	fields, err := proto.Decode(body)
	if err != nil {
		return "", err
	}
	return proto.FormatFields(fields, ""), nil
}

// ==================== Compare ====================

func (a *App) CompareFlows(idA, idB string) (*compare.Comparison, error) {
	fA, err := a.store.GetFlow(idA)
	if err != nil {
		return nil, fmt.Errorf("flow %s: %w", idA, err)
	}
	fB, err := a.store.GetFlow(idB)
	if err != nil {
		return nil, fmt.Errorf("flow %s: %w", idB, err)
	}
	return compare.Compare(fA, fB), nil
}

// ==================== Traffic Stats ====================

func (a *App) GetTrafficStats() *stats.Summary {
	flows, _ := a.store.ListFlows(types.FlowFilter{Limit: 10000})
	return stats.Compute(flows)
}

// ==================== API Grouping ====================

func (a *App) GetAPIGroups() []grouping.APIGroup {
	flows, _ := a.store.ListFlows(types.FlowFilter{Limit: 5000})
	return grouping.GroupFlows(flows)
}

// ==================== Import ====================

func (a *App) ImportHARFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	flows, err := importer.ImportHAR(f)
	if err != nil {
		return 0, err
	}
	for _, fl := range flows {
		a.store.SaveFlow(fl)
	}
	return len(flows), nil
}

// ==================== Sequences ====================

func (a *App) CreateSequence(name string, flowIDs []string) error {
	var flows []*types.Flow
	for _, id := range flowIDs {
		f, err := a.store.GetFlow(id)
		if err != nil {
			return err
		}
		flows = append(flows, f)
	}
	seq := sequence.FromFlows(name, flows)
	return sequence.Save(seq, filepath.Join(a.certDir, "sequences"))
}

func (a *App) ListSequences() ([]string, error) {
	return sequence.ListSaved(filepath.Join(a.certDir, "sequences"))
}

func (a *App) ReplaySequence(name string) (*sequence.ReplayResult, error) {
	seq, err := sequence.Load(name, filepath.Join(a.certDir, "sequences"))
	if err != nil {
		return nil, err
	}
	return sequence.Replay(seq, sequence.ReplayOptions{Timeout: 30 * time.Second})
}
