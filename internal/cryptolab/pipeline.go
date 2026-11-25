package cryptolab

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const stepPreviewMaxBytes = 65536

// ListOperations returns the full self-describing catalog of composable pipeline
// operations so GUI and CLI clients can render dynamic operation cards.
func ListOperations() []OperationSpec {
	keyEncParam := OperationParamSpec{
		Name: "key_encoding", Label: "Key Encoding", Type: "select",
		Default: "utf8", Options: []string{"utf8", "hex", "base64"},
	}
	cipherKeyEncParam := OperationParamSpec{
		Name: "key_encoding", Label: "Key Encoding", Type: "select",
		Default: "hex", Options: []string{"hex", "utf8", "base64"},
	}
	ivEncParam := OperationParamSpec{
		Name: "iv_encoding", Label: "IV / Nonce Encoding", Type: "select",
		Default: "hex", Options: []string{"hex", "utf8", "base64"},
	}
	digestOutParam := OperationParamSpec{
		Name: "output_encoding", Label: "Output Encoding", Type: "select",
		Default: "hex", Options: []string{"hex", "hex_upper", "base64", "raw"},
	}
	aesModeParam := OperationParamSpec{
		Name: "mode", Label: "Mode", Type: "select",
		Default: "cbc", Options: []string{"ecb", "cbc", "ctr", "cfb", "ofb", "gcm"},
	}
	sm4ModeParam := OperationParamSpec{
		Name: "mode", Label: "Mode", Type: "select",
		Default: "cbc", Options: []string{"ecb", "cbc", "ctr"},
	}
	paddingParam := OperationParamSpec{
		Name: "padding", Label: "Padding", Type: "select",
		Default: "pkcs7", Options: []string{"pkcs7", "zero", "none"},
	}

	return []OperationSpec{
		// ── Codecs ──
		{
			Name: "base64_encode", Category: "codec", Label: "Base64 Encode",
			Description: "Encode bytes to Base64 with optional custom 64-char alphabet and no-padding mode.",
			Params: []OperationParamSpec{
				{Name: "alphabet", Label: "Alphabet", Type: "string", Default: "standard", Placeholder: "standard, url, or 64-char custom alphabet"},
				{Name: "raw", Label: "No Padding (Raw)", Type: "boolean", Default: "false"},
			},
		},
		{
			Name: "base64_decode", Category: "codec", Label: "Base64 Decode",
			Description: "Decode Base64 with optional custom 64-char alphabet and no-padding mode.",
			Params: []OperationParamSpec{
				{Name: "alphabet", Label: "Alphabet", Type: "string", Default: "standard", Placeholder: "standard, url, or 64-char custom alphabet"},
				{Name: "raw", Label: "No Padding (Raw)", Type: "boolean", Default: "false"},
			},
		},
		{
			Name: "hex_encode", Category: "codec", Label: "Hex Encode",
			Description: "Encode raw bytes as hexadecimal characters.",
			Params: []OperationParamSpec{
				{Name: "uppercase", Label: "Uppercase", Type: "boolean", Default: "false"},
				{Name: "delimiter", Label: "Delimiter", Type: "string", Default: "", Placeholder: "optional separator e.g. space or :"},
			},
		},
		{
			Name: "hex_decode", Category: "codec", Label: "Hex Decode",
			Description: "Decode hexadecimal text (tolerates whitespace, 0x prefixes, and :/-/, separators).",
		},
		{
			Name: "url_encode", Category: "codec", Label: "URL Encode",
			Description: "Percent-encode bytes for query, path, or all-byte encoding.",
			Params: []OperationParamSpec{
				{Name: "mode", Label: "Mode", Type: "select", Default: "query", Options: []string{"query", "path", "all"}},
			},
		},
		{
			Name: "url_decode", Category: "codec", Label: "URL Decode",
			Description: "Decode URL percent-encoded strings.",
			Params: []OperationParamSpec{
				{Name: "mode", Label: "Mode", Type: "select", Default: "query", Options: []string{"query", "path"}},
			},
		},
		{
			Name: "base32_encode", Category: "codec", Label: "Base32 Encode",
			Description: "Encode bytes to Base32 (standard, hex, or custom 32-char alphabet).",
			Params: []OperationParamSpec{
				{Name: "alphabet", Label: "Alphabet", Type: "string", Default: "standard", Placeholder: "standard, hex, or 32-char custom alphabet"},
				{Name: "raw", Label: "No Padding (Raw)", Type: "boolean", Default: "false"},
			},
		},
		{
			Name: "base32_decode", Category: "codec", Label: "Base32 Decode",
			Description: "Decode Base32 (standard, hex, or custom 32-char alphabet).",
			Params: []OperationParamSpec{
				{Name: "alphabet", Label: "Alphabet", Type: "string", Default: "standard", Placeholder: "standard, hex, or 32-char custom alphabet"},
				{Name: "raw", Label: "No Padding (Raw)", Type: "boolean", Default: "false"},
			},
		},

		// ── Compression ──
		{
			Name: "gzip_compress", Category: "compression", Label: "Gzip Compress",
			Description: "Compress payload using Gzip.",
			Params: []OperationParamSpec{
				{Name: "level", Label: "Level (-1..9)", Type: "number", Default: "-1"},
			},
		},
		{
			Name: "gzip_decompress", Category: "compression", Label: "Gzip Decompress",
			Description: "Decompress Gzip payload (bounded to 16 MiB).",
		},
		{
			Name: "zlib_compress", Category: "compression", Label: "Zlib Compress",
			Description: "Compress payload using Zlib (RFC 1950).",
			Params: []OperationParamSpec{
				{Name: "level", Label: "Level (-1..9)", Type: "number", Default: "-1"},
			},
		},
		{
			Name: "zlib_decompress", Category: "compression", Label: "Zlib Decompress",
			Description: "Decompress Zlib payload (bounded to 16 MiB).",
		},
		{
			Name: "deflate_compress", Category: "compression", Label: "Deflate Compress",
			Description: "Compress payload using raw DEFLATE (RFC 1951).",
			Params: []OperationParamSpec{
				{Name: "level", Label: "Level (-1..9)", Type: "number", Default: "-1"},
			},
		},
		{
			Name: "deflate_decompress", Category: "compression", Label: "Deflate Decompress",
			Description: "Decompress raw DEFLATE payload (bounded to 16 MiB).",
		},

		// ── XOR ──
		{
			Name: "xor", Category: "xor", Label: "XOR (Repeating Key)",
			Description: "XOR payload against a repeating UTF-8, hex, or base64 key.",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key", Type: "string", Required: true, Placeholder: "key material"},
				keyEncParam,
			},
		},
		{
			Name: "xor_bruteforce", Category: "xor", Label: "XOR Brute Force (Single-Byte)",
			Description: "Score all 256 single-byte XOR keys by printable ASCII frequency.",
			Params: []OperationParamSpec{
				{Name: "top_n", Label: "Top N Candidates", Type: "number", Default: "5"},
				{Name: "output_mode", Label: "Output Mode", Type: "select", Default: "json", Options: []string{"json", "best"}},
			},
		},

		// ── Hashes & HMAC ──
		{
			Name: "md5", Category: "hash", Label: "MD5 (Custom IV Supported)",
			Description: "Compute MD5 digest; optionally override the 4x32-bit LE initial chaining state via iv_hex.",
			Params: []OperationParamSpec{
				{Name: "iv_hex", Label: "Custom IV (32 hex chars, 4x32-bit LE)", Type: "hex", Placeholder: "0123456789abcdeffedcba9876543210"},
				digestOutParam,
			},
		},
		{
			Name: "sha1", Category: "hash", Label: "SHA-1",
			Description: "Compute SHA-1 digest.",
			Params:      []OperationParamSpec{digestOutParam},
		},
		{
			Name: "sha256", Category: "hash", Label: "SHA-256 (Custom IV Supported)",
			Description: "Compute SHA-256 digest; optionally override the 8x32-bit BE initial hash state via iv_hex.",
			Params: []OperationParamSpec{
				{Name: "iv_hex", Label: "Custom IV (64 hex chars, 8x32-bit BE)", Type: "hex", Placeholder: "6a09e667bb67ae853c6ef372a54ff53a..."},
				digestOutParam,
			},
		},
		{
			Name: "sha512", Category: "hash", Label: "SHA-512",
			Description: "Compute SHA-512 digest.",
			Params:      []OperationParamSpec{digestOutParam},
		},
		{
			Name: "hmac_md5", Category: "hmac", Label: "HMAC-MD5",
			Description: "Compute HMAC-MD5 with a secret key.",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Secret Key", Type: "string", Required: true},
				keyEncParam,
				digestOutParam,
			},
		},
		{
			Name: "hmac_sha1", Category: "hmac", Label: "HMAC-SHA1",
			Description: "Compute HMAC-SHA1 with a secret key.",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Secret Key", Type: "string", Required: true},
				keyEncParam,
				digestOutParam,
			},
		},
		{
			Name: "hmac_sha256", Category: "hmac", Label: "HMAC-SHA256",
			Description: "Compute HMAC-SHA256 with a secret key.",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Secret Key", Type: "string", Required: true},
				keyEncParam,
				digestOutParam,
			},
		},
		{
			Name: "hmac_sha512", Category: "hmac", Label: "HMAC-SHA512",
			Description: "Compute HMAC-SHA512 with a secret key.",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Secret Key", Type: "string", Required: true},
				keyEncParam,
				digestOutParam,
			},
		},
		{
			Name: "crc32", Category: "hash", Label: "CRC-32",
			Description: "Compute CRC-32 checksum (IEEE, Castagnoli, or Koopman).",
			Params: []OperationParamSpec{
				{Name: "polynomial", Label: "Polynomial", Type: "select", Default: "ieee", Options: []string{"ieee", "castagnoli", "koopman"}},
				digestOutParam,
			},
		},

		// ── Symmetric Ciphers ──
		{
			Name: "aes_encrypt", Category: "cipher", Label: "AES Encrypt",
			Description: "Encrypt using AES-128/192/256 (ECB, CBC, CTR, CFB, OFB, GCM).",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key (16/24/32 bytes)", Type: "hex", Required: true},
				cipherKeyEncParam,
				{Name: "iv", Label: "IV / Nonce", Type: "hex", Placeholder: "16 bytes (12 bytes for GCM)"},
				ivEncParam,
				aesModeParam,
				paddingParam,
				{Name: "aad_hex", Label: "GCM AAD (Hex)", Type: "hex", Placeholder: "optional additional authenticated data"},
			},
		},
		{
			Name: "aes_decrypt", Category: "cipher", Label: "AES Decrypt",
			Description: "Decrypt using AES-128/192/256 (ECB, CBC, CTR, CFB, OFB, GCM).",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key (16/24/32 bytes)", Type: "hex", Required: true},
				cipherKeyEncParam,
				{Name: "iv", Label: "IV / Nonce", Type: "hex", Placeholder: "16 bytes (12 bytes for GCM)"},
				ivEncParam,
				aesModeParam,
				paddingParam,
				{Name: "aad_hex", Label: "GCM AAD (Hex)", Type: "hex", Placeholder: "optional additional authenticated data"},
			},
		},
		{
			Name: "sm4_encrypt", Category: "cipher", Label: "SM4 Encrypt (GB/T 32907)",
			Description: "Encrypt using standard pure-Go SM4 (ECB, CBC, CTR).",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key (16 bytes)", Type: "hex", Required: true},
				cipherKeyEncParam,
				{Name: "iv", Label: "IV / Counter (16 bytes)", Type: "hex"},
				ivEncParam,
				sm4ModeParam,
				paddingParam,
			},
		},
		{
			Name: "sm4_decrypt", Category: "cipher", Label: "SM4 Decrypt (GB/T 32907)",
			Description: "Decrypt using standard pure-Go SM4 (ECB, CBC, CTR).",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key (16 bytes)", Type: "hex", Required: true},
				cipherKeyEncParam,
				{Name: "iv", Label: "IV / Counter (16 bytes)", Type: "hex"},
				ivEncParam,
				sm4ModeParam,
				paddingParam,
			},
		},
		{
			Name: "chacha20_encrypt", Category: "cipher", Label: "ChaCha20 Encrypt",
			Description: "Encrypt using RFC 8439 ChaCha20 (32-byte key, 12-byte nonce).",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key (32 bytes)", Type: "hex", Required: true},
				cipherKeyEncParam,
				{Name: "nonce", Label: "Nonce (12 bytes)", Type: "hex", Required: true},
				ivEncParam,
				{Name: "counter", Label: "Initial Counter", Type: "number", Default: "0"},
			},
		},
		{
			Name: "chacha20_decrypt", Category: "cipher", Label: "ChaCha20 Decrypt",
			Description: "Decrypt using RFC 8439 ChaCha20 (32-byte key, 12-byte nonce).",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key (32 bytes)", Type: "hex", Required: true},
				cipherKeyEncParam,
				{Name: "nonce", Label: "Nonce (12 bytes)", Type: "hex", Required: true},
				ivEncParam,
				{Name: "counter", Label: "Initial Counter", Type: "number", Default: "0"},
			},
		},
		{
			Name: "rc4_encrypt", Category: "cipher", Label: "RC4 / RC4-dropN Encrypt",
			Description: "Encrypt using RC4 with optional initial keystream byte drop.",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key (1..256 bytes)", Type: "hex", Required: true},
				cipherKeyEncParam,
				{Name: "drop", Label: "Drop Initial Keystream Bytes", Type: "number", Default: "0"},
			},
		},
		{
			Name: "rc4_decrypt", Category: "cipher", Label: "RC4 / RC4-dropN Decrypt",
			Description: "Decrypt using RC4 with optional initial keystream byte drop.",
			Params: []OperationParamSpec{
				{Name: "key", Label: "Key (1..256 bytes)", Type: "hex", Required: true},
				cipherKeyEncParam,
				{Name: "drop", Label: "Drop Initial Keystream Bytes", Type: "number", Default: "0"},
			},
		},

		// ── Protobuf ──
		{
			Name: "protobuf_decode", Category: "protobuf", Label: "Protobuf Wire Decode (Schema-less)",
			Description: "Decode raw Protobuf wire bytes into an indented JSON AST without a .proto schema.",
		},
	}
}

// RunPipeline executes an ordered chain of CyberChef-style operations, recording
// per-step previews, lengths, timings, and precise error attribution.
func RunPipeline(req PipelineRequest) *PipelineResult {
	totalStart := time.Now()
	res := &PipelineResult{
		Success:    false,
		FailedStep: -1,
		Steps:      make([]PipelineStepResult, 0, len(req.Steps)),
	}

	cur, err := decodeParamBytes(req.Input, req.InputEncoding)
	if err != nil {
		res.Error = fmt.Sprintf("input decode (%s): %v", req.InputEncoding, err)
		res.TotalElapsedUS = time.Since(totalStart).Microseconds()
		return res
	}

	for idx, step := range req.Steps {
		if step.Disabled {
			res.Steps = append(res.Steps, PipelineStepResult{
				Index:      idx,
				Op:         step.Op,
				Disabled:   true,
				OutputUTF8: safeUTF8Preview(cur, stepPreviewMaxBytes),
				OutputHex:  hexPreview(cur, stepPreviewMaxBytes),
				ByteLen:    len(cur),
				ElapsedUS:  0,
			})
			continue
		}

		stepStart := time.Now()
		next, stepErr := executePipelineStep(cur, step)
		elapsed := time.Since(stepStart).Microseconds()

		if stepErr != nil {
			res.Steps = append(res.Steps, PipelineStepResult{
				Index:     idx,
				Op:        step.Op,
				ByteLen:   len(cur),
				ElapsedUS: elapsed,
				Error:     stepErr.Error(),
			})
			res.FailedStep = idx
			res.Error = fmt.Sprintf("step %d (%s): %v", idx, step.Op, stepErr)
			res.TotalElapsedUS = time.Since(totalStart).Microseconds()
			return res
		}

		cur = next
		res.Steps = append(res.Steps, PipelineStepResult{
			Index:      idx,
			Op:         step.Op,
			OutputUTF8: safeUTF8Preview(cur, stepPreviewMaxBytes),
			OutputHex:  hexPreview(cur, stepPreviewMaxBytes),
			ByteLen:    len(cur),
			ElapsedUS:  elapsed,
		})
	}

	res.Success = true
	res.FailedStep = -1
	res.OutputUTF8 = string(cur)
	res.OutputHex = hex.EncodeToString(cur)
	res.OutputBase64 = base64.StdEncoding.EncodeToString(cur)
	res.ByteLen = len(cur)
	res.TotalElapsedUS = time.Since(totalStart).Microseconds()
	return res
}

func executePipelineStep(data []byte, step PipelineStep) ([]byte, error) {
	p := step.Params
	op := strings.ToLower(strings.TrimSpace(step.Op))

	switch op {
	case "base64_encode":
		return Base64Encode(data, p["alphabet"], parseBoolParam(p["raw"]))
	case "base64_decode":
		return Base64Decode(data, p["alphabet"], parseBoolParam(p["raw"]))
	case "hex_encode":
		return HexEncode(data, parseBoolParam(p["uppercase"]), p["delimiter"]), nil
	case "hex_decode":
		return HexDecode(data)
	case "url_encode":
		return URLEncode(data, p["mode"]), nil
	case "url_decode":
		return URLDecode(data, p["mode"])
	case "base32_encode":
		return Base32Encode(data, p["alphabet"], parseBoolParam(p["raw"]))
	case "base32_decode":
		return Base32Decode(data, p["alphabet"], parseBoolParam(p["raw"]))

	case "gzip_compress":
		return GzipCompress(data, parseIntParam(p["level"], -1))
	case "gzip_decompress":
		return GzipDecompress(data)
	case "zlib_compress":
		return ZlibCompress(data, parseIntParam(p["level"], -1))
	case "zlib_decompress":
		return ZlibDecompress(data)
	case "deflate_compress":
		return DeflateCompress(data, parseIntParam(p["level"], -1))
	case "deflate_decompress":
		return DeflateDecompress(data)

	case "xor":
		key, err := decodeParamBytes(p["key"], p["key_encoding"])
		if err != nil {
			return nil, fmt.Errorf("xor key: %w", err)
		}
		return XORBytes(data, key)
	case "xor_bruteforce":
		topN := parseIntParam(p["top_n"], 5)
		cands := XORBruteforce(data, topN)
		if len(cands) == 0 {
			return nil, fmt.Errorf("xor_bruteforce: input is empty")
		}
		if strings.EqualFold(strings.TrimSpace(p["output_mode"]), "best") {
			return XORBytes(data, []byte{cands[0].KeyByte})
		}
		out, err := json.MarshalIndent(cands, "", "  ")
		if err != nil {
			return nil, err
		}
		return out, nil

	case "md5":
		sum, err := MD5Sum(data, p["iv_hex"])
		if err != nil {
			return nil, err
		}
		return formatDigestOutput(sum, p["output_encoding"])
	case "sha1":
		sum := SHA1Sum(data)
		return formatDigestOutput(sum[:], p["output_encoding"])
	case "sha256":
		sum, err := SHA256Sum(data, p["iv_hex"])
		if err != nil {
			return nil, err
		}
		return formatDigestOutput(sum, p["output_encoding"])
	case "sha512":
		sum := SHA512Sum(data)
		return formatDigestOutput(sum[:], p["output_encoding"])
	case "hmac_md5", "hmac_sha1", "hmac_sha256", "hmac_sha512":
		key, err := decodeParamBytes(p["key"], p["key_encoding"])
		if err != nil {
			return nil, fmt.Errorf("%s key: %w", op, err)
		}
		sum, err := HMACSum(op, data, key)
		if err != nil {
			return nil, err
		}
		return formatDigestOutput(sum, p["output_encoding"])
	case "crc32":
		v, err := CRC32Sum(data, p["polynomial"])
		if err != nil {
			return nil, err
		}
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], v)
		return formatDigestOutput(buf[:], p["output_encoding"])

	case "aes_encrypt", "aes_decrypt":
		key, iv, aad, err := parseCipherParams(p)
		if err != nil {
			return nil, err
		}
		if op == "aes_encrypt" {
			return AESEncrypt(data, key, iv, p["mode"], p["padding"], aad)
		}
		return AESDecrypt(data, key, iv, p["mode"], p["padding"], aad)

	case "sm4_encrypt", "sm4_decrypt":
		key, iv, _, err := parseCipherParams(p)
		if err != nil {
			return nil, err
		}
		if op == "sm4_encrypt" {
			return SM4Encrypt(data, key, iv, p["mode"], p["padding"])
		}
		return SM4Decrypt(data, key, iv, p["mode"], p["padding"])

	case "chacha20_encrypt", "chacha20_decrypt":
		keyEnc := defaultStr(p["key_encoding"], "hex")
		key, err := decodeParamBytes(p["key"], keyEnc)
		if err != nil {
			return nil, fmt.Errorf("chacha20 key: %w", err)
		}
		nonceStr := p["nonce"]
		if nonceStr == "" {
			nonceStr = p["iv"]
		}
		ivEnc := defaultStr(p["iv_encoding"], "hex")
		nonce, err := decodeParamBytes(nonceStr, ivEnc)
		if err != nil {
			return nil, fmt.Errorf("chacha20 nonce: %w", err)
		}
		var ctr uint32
		if s := strings.TrimSpace(p["counter"]); s != "" {
			v, err := strconv.ParseUint(s, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("chacha20 counter: %w", err)
			}
			ctr = uint32(v)
		}
		return ChaCha20XOR(data, key, nonce, ctr)

	case "rc4_encrypt", "rc4_decrypt":
		keyEnc := defaultStr(p["key_encoding"], "hex")
		key, err := decodeParamBytes(p["key"], keyEnc)
		if err != nil {
			return nil, fmt.Errorf("rc4 key: %w", err)
		}
		drop := parseIntParam(p["drop"], 0)
		return RC4XOR(data, key, drop)

	case "protobuf_decode":
		node, err := DecodeProtobufRaw(data)
		if err != nil {
			return nil, err
		}
		return json.MarshalIndent(node, "", "  ")

	default:
		return nil, fmt.Errorf("unknown pipeline operation %q", step.Op)
	}
}

func parseCipherParams(p map[string]string) (key, iv, aad []byte, err error) {
	keyEnc := defaultStr(p["key_encoding"], "hex")
	key, err = decodeParamBytes(p["key"], keyEnc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cipher key: %w", err)
	}
	ivEnc := defaultStr(p["iv_encoding"], "hex")
	ivRaw := p["iv"]
	if ivRaw == "" {
		ivRaw = p["nonce"]
	}
	if ivRaw != "" {
		iv, err = decodeParamBytes(ivRaw, ivEnc)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cipher iv/nonce: %w", err)
		}
	}
	if aadHex := strings.TrimSpace(p["aad_hex"]); aadHex != "" {
		aad, err = HexDecode([]byte(aadHex))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cipher aad_hex: %w", err)
		}
	}
	return key, iv, aad, nil
}

func parseBoolParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseIntParam(v string, fallback int) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func defaultStr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func hexPreview(data []byte, maxBytes int) string {
	if len(data) <= maxBytes {
		return hex.EncodeToString(data)
	}
	return hex.EncodeToString(data[:maxBytes]) + "..."
}
