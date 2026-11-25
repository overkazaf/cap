package wailsgui

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/overkazaf/cap/internal/cryptolab"
)

// ==================== CryptoLab Workbench ====================

// ListCryptoOperations returns the self-describing catalog of composable pipeline operations.
func (a *App) ListCryptoOperations() []cryptolab.OperationSpec {
	return cryptolab.ListOperations()
}

// RunCryptoPipeline executes a CyberChef-style ordered transformation pipeline.
func (a *App) RunCryptoPipeline(req cryptolab.PipelineRequest) *cryptolab.PipelineResult {
	return cryptolab.RunPipeline(req)
}

// IdentifyCryptoPayload runs multi-format heuristics, entropy analysis, JWT decoding,
// and recipe recommendations over an arbitrary input string.
func (a *App) IdentifyCryptoPayload(input string) *cryptolab.IdentifyResult {
	return cryptolab.IdentifyPayload(input)
}

// DecodeProtobufRawHex decodes raw Protobuf wire bytes without a .proto schema.
// It accepts hexadecimal text (tolerating whitespace, 0x prefixes, and separators)
// as well as standard, raw, or URL-safe Base64 as a fallback.
func (a *App) DecodeProtobufRawHex(hexOrB64 string) (*cryptolab.ProtoMessageNode, error) {
	trimmed := strings.TrimSpace(hexOrB64)
	if trimmed == "" {
		return nil, fmt.Errorf("protobuf payload is empty")
	}

	var hexErr, protoFromHexErr error
	if rawHex, err := cryptolab.HexDecode([]byte(trimmed)); err == nil && len(rawHex) > 0 {
		node, perr := cryptolab.DecodeProtobufRaw(rawHex)
		if perr == nil {
			return node, nil
		}
		protoFromHexErr = perr
	} else {
		hexErr = err
	}

	compact := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		default:
			return r
		}
	}, trimmed)

	var protoFromB64Err error
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		rawB64, err := enc.DecodeString(compact)
		if err != nil || len(rawB64) == 0 {
			continue
		}
		node, perr := cryptolab.DecodeProtobufRaw(rawB64)
		if perr == nil {
			return node, nil
		}
		if protoFromB64Err == nil {
			protoFromB64Err = perr
		}
	}

	if protoFromHexErr != nil {
		return nil, protoFromHexErr
	}
	if protoFromB64Err != nil {
		return nil, protoFromB64Err
	}
	if hexErr != nil {
		return nil, fmt.Errorf("decode protobuf payload as hex or base64: %w", hexErr)
	}
	return nil, fmt.Errorf("protobuf payload could not be decoded as hex or base64")
}

// EncodeProtobufRawHex serializes a ProtoMessageNode back into lowercase hex wire bytes.
func (a *App) EncodeProtobufRawHex(node cryptolab.ProtoMessageNode) (string, error) {
	raw, err := cryptolab.EncodeProtobufRaw(&node)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// SolveAES128DFA recovers the AES-128 Round-10 subkey and Master Key via Round-9 DFA.
func (a *App) SolveAES128DFA(req cryptolab.DFARequest) (*cryptolab.DFAResult, error) {
	return cryptolab.SolveAES128DFA(req)
}

// GenerateDFAFaultScript generates a Unidbg (Java) or Qiling (Python) Round-9 DFA
// fault-injection harness script.
func (a *App) GenerateDFAFaultScript(engine string, cfg cryptolab.DFAScriptConfig) *cryptolab.GeneratedDFAScript {
	return cryptolab.GenerateDFAFaultScript(engine, cfg)
}
