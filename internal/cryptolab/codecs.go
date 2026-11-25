package cryptolab

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"math/bits"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxDecompressedBytes caps gzip/zlib/deflate decompression output (16 MiB) to protect
// against zip-bomb payloads.
const MaxDecompressedBytes = 16 << 20

const (
	stdBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	urlBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	stdBase32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	hexBase32Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
)

// DefaultMD5IV is the standard RFC 1321 MD5 initial chaining state (4 x 32-bit LE words).
var DefaultMD5IV = [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}

// DefaultSHA256IV is the standard FIPS 180-4 SHA-256 initial hash values (8 x 32-bit BE words).
var DefaultSHA256IV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var (
	uuidRe       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	pctEncodedRe = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	pureHexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// ─── Base64 / Base32 / Hex / URL Codecs ──────────────────────────────────────

func buildBase64Encoding(alphabet string, raw bool) (*base64.Encoding, error) {
	alpha := strings.TrimSpace(alphabet)
	switch strings.ToLower(alpha) {
	case "", "std", "standard":
		alpha = stdBase64Alphabet
	case "url", "urlsafe", "url_safe":
		alpha = urlBase64Alphabet
	}
	if len(alpha) != 64 {
		return nil, fmt.Errorf("base64 custom alphabet must be exactly 64 characters, got %d", len(alpha))
	}
	var seen [256]bool
	hasEq := false
	for i := 0; i < 64; i++ {
		c := alpha[i]
		if c == '\r' || c == '\n' {
			return nil, fmt.Errorf("base64 alphabet cannot contain CR or LF")
		}
		if seen[c] {
			return nil, fmt.Errorf("base64 alphabet contains duplicate byte 0x%02x", c)
		}
		seen[c] = true
		if c == '=' {
			hasEq = true
		}
	}
	enc := base64.NewEncoding(alpha)
	if raw || hasEq {
		enc = enc.WithPadding(base64.NoPadding)
	}
	return enc, nil
}

// Base64Encode encodes data using standard, URL-safe, or custom 64-char alphabet.
func Base64Encode(data []byte, alphabet string, raw bool) ([]byte, error) {
	enc, err := buildBase64Encoding(alphabet, raw)
	if err != nil {
		return nil, err
	}
	out := make([]byte, enc.EncodedLen(len(data)))
	enc.Encode(out, data)
	return out, nil
}

// Base64Decode decodes data using standard, URL-safe, or custom 64-char alphabet.
func Base64Decode(data []byte, alphabet string, raw bool) ([]byte, error) {
	cleaned := stripWhitespace(string(data))
	enc, err := buildBase64Encoding(alphabet, raw)
	if err != nil {
		return nil, err
	}
	if !raw && !strings.Contains(cleaned, "=") && len(cleaned)%4 != 0 {
		enc = enc.WithPadding(base64.NoPadding)
	}
	out, err := enc.DecodeString(cleaned)
	if err != nil {
		// Retry without padding in case unpadded input had length divisible by 4 or trailing '=' mismatch.
		if raw {
			trimmed := strings.TrimRight(cleaned, "=")
			if out2, err2 := enc.DecodeString(trimmed); err2 == nil {
				return out2, nil
			}
		} else {
			rawEnc := enc.WithPadding(base64.NoPadding)
			if out2, err2 := rawEnc.DecodeString(strings.TrimRight(cleaned, "=")); err2 == nil {
				return out2, nil
			}
		}
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return out, nil
}

func buildBase32Encoding(alphabet string, raw bool) (*base32.Encoding, error) {
	alpha := strings.TrimSpace(alphabet)
	switch strings.ToLower(alpha) {
	case "", "std", "standard":
		alpha = stdBase32Alphabet
	case "hex":
		alpha = hexBase32Alphabet
	}
	if len(alpha) != 32 {
		return nil, fmt.Errorf("base32 custom alphabet must be exactly 32 characters, got %d", len(alpha))
	}
	var seen [256]bool
	hasEq := false
	for i := 0; i < 32; i++ {
		c := alpha[i]
		if c == '\r' || c == '\n' {
			return nil, fmt.Errorf("base32 alphabet cannot contain CR or LF")
		}
		if seen[c] {
			return nil, fmt.Errorf("base32 alphabet contains duplicate byte 0x%02x", c)
		}
		seen[c] = true
		if c == '=' {
			hasEq = true
		}
	}
	enc := base32.NewEncoding(alpha)
	if raw || hasEq {
		enc = enc.WithPadding(base32.NoPadding)
	}
	return enc, nil
}

// Base32Encode encodes data using standard, hex, or custom 32-char alphabet.
func Base32Encode(data []byte, alphabet string, raw bool) ([]byte, error) {
	enc, err := buildBase32Encoding(alphabet, raw)
	if err != nil {
		return nil, err
	}
	out := make([]byte, enc.EncodedLen(len(data)))
	enc.Encode(out, data)
	return out, nil
}

// Base32Decode decodes data using standard, hex, or custom 32-char alphabet.
func Base32Decode(data []byte, alphabet string, raw bool) ([]byte, error) {
	cleaned := stripWhitespace(string(data))
	lowerAlpha := strings.ToLower(strings.TrimSpace(alphabet))
	if lowerAlpha == "" || lowerAlpha == "std" || lowerAlpha == "standard" || lowerAlpha == "hex" {
		cleaned = strings.ToUpper(cleaned)
	}
	enc, err := buildBase32Encoding(alphabet, raw)
	if err != nil {
		return nil, err
	}
	if !raw && !strings.Contains(cleaned, "=") && len(cleaned)%8 != 0 {
		enc = enc.WithPadding(base32.NoPadding)
	}
	out, err := enc.DecodeString(cleaned)
	if err != nil {
		rawEnc := enc.WithPadding(base32.NoPadding)
		if out2, err2 := rawEnc.DecodeString(strings.TrimRight(cleaned, "=")); err2 == nil {
			return out2, nil
		}
		return nil, fmt.Errorf("base32 decode: %w", err)
	}
	return out, nil
}

// HexEncode encodes raw bytes as hex with optional uppercase and byte delimiter.
func HexEncode(data []byte, uppercase bool, delimiter string) []byte {
	if len(data) == 0 {
		return nil
	}
	raw := hex.EncodeToString(data)
	if uppercase {
		raw = strings.ToUpper(raw)
	}
	if delimiter == "" {
		return []byte(raw)
	}
	var sb strings.Builder
	sb.Grow(len(raw) + (len(data)-1)*len(delimiter))
	for i := 0; i < len(raw); i += 2 {
		if i > 0 {
			sb.WriteString(delimiter)
		}
		sb.WriteString(raw[i : i+2])
	}
	return []byte(sb.String())
}

// HexDecode decodes hex text, tolerating whitespace, 0x prefixes, and : / - / , delimiters.
func HexDecode(data []byte) ([]byte, error) {
	cleaned := cleanHexString(string(data))
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("hex decode: odd length (%d hex characters)", len(cleaned))
	}
	out, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	return out, nil
}

func cleanHexString(s string) string {
	s = strings.TrimSpace(s)
	var sb strings.Builder
	sb.Grow(len(s))
	atTokenStart := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\r', '\n', ':', '-', ',':
			atTokenStart = true
			continue
		}
		if atTokenStart && c == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') {
			i++ // skip 'x'/'X' prefix at token start only
			atTokenStart = false
			continue
		}
		sb.WriteByte(c)
		atTokenStart = false
	}
	return sb.String()
}

// URLEncode encodes data using query (default), path, or all-byte percent-encoding.
func URLEncode(data []byte, mode string) []byte {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "path":
		return []byte(url.PathEscape(string(data)))
	case "all":
		var sb strings.Builder
		sb.Grow(len(data) * 3)
		const digits = "0123456789ABCDEF"
		for _, b := range data {
			sb.WriteByte('%')
			sb.WriteByte(digits[b>>4])
			sb.WriteByte(digits[b&0x0f])
		}
		return []byte(sb.String())
	default:
		return []byte(url.QueryEscape(string(data)))
	}
}

// URLDecode decodes percent-encoded strings using query (default) or path rules.
func URLDecode(data []byte, mode string) ([]byte, error) {
	var (
		s   string
		err error
	)
	if strings.EqualFold(strings.TrimSpace(mode), "path") {
		s, err = url.PathUnescape(string(data))
	} else {
		s, err = url.QueryUnescape(string(data))
	}
	if err != nil {
		return nil, fmt.Errorf("url decode: %w", err)
	}
	return []byte(s), nil
}

// ─── Compression (Bounded Decompression) ─────────────────────────────────────

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(r, limit+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("decompressed payload exceeds maximum allowed size (%d bytes)", limit)
	}
	return out, nil
}

func normalizeCompressLevel(level int) int {
	if level == 0 {
		return flate.DefaultCompression
	}
	if level < flate.HuffmanOnly {
		return flate.DefaultCompression
	}
	if level > flate.BestCompression {
		return flate.BestCompression
	}
	return level
}

// GzipCompress compresses data in gzip format.
func GzipCompress(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, normalizeCompressLevel(level))
	if err != nil {
		return nil, fmt.Errorf("gzip compress: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("gzip compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip compress close: %w", err)
	}
	return buf.Bytes(), nil
}

// GzipDecompress decompresses gzip data with a 16 MiB output cap.
func GzipDecompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip decompress: %w", err)
	}
	defer r.Close()
	out, err := readBounded(r, MaxDecompressedBytes)
	if err != nil {
		return nil, fmt.Errorf("gzip decompress: %w", err)
	}
	return out, nil
}

// ZlibCompress compresses data in zlib format (RFC 1950).
func ZlibCompress(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, normalizeCompressLevel(level))
	if err != nil {
		return nil, fmt.Errorf("zlib compress: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("zlib compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("zlib compress close: %w", err)
	}
	return buf.Bytes(), nil
}

// ZlibDecompress decompresses zlib data with a 16 MiB output cap.
func ZlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zlib decompress: %w", err)
	}
	defer r.Close()
	out, err := readBounded(r, MaxDecompressedBytes)
	if err != nil {
		return nil, fmt.Errorf("zlib decompress: %w", err)
	}
	return out, nil
}

// DeflateCompress compresses data using raw DEFLATE (RFC 1951).
func DeflateCompress(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, normalizeCompressLevel(level))
	if err != nil {
		return nil, fmt.Errorf("deflate compress: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("deflate compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("deflate compress close: %w", err)
	}
	return buf.Bytes(), nil
}

// DeflateDecompress decompresses raw DEFLATE data with a 16 MiB output cap.
func DeflateDecompress(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	out, err := readBounded(r, MaxDecompressedBytes)
	if err != nil {
		return nil, fmt.Errorf("deflate decompress: %w", err)
	}
	return out, nil
}

// ─── XOR & Single-Byte XOR Bruteforce ────────────────────────────────────────

// XORBytes applies a repeating-key XOR to data.
func XORBytes(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("xor: key must not be empty")
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out, nil
}

// XORBruteforce scores all 256 single-byte XOR keys by printable ASCII and English
// character frequency, returning the topN highest-scoring candidates.
func XORBruteforce(data []byte, topN int) []XORCandidate {
	if topN <= 0 {
		topN = 5
	}
	if topN > 256 {
		topN = 256
	}
	if len(data) == 0 {
		return nil
	}

	candidates := make([]XORCandidate, 0, 256)
	buf := make([]byte, len(data))
	for k := 0; k < 256; k++ {
		kb := byte(k)
		for i, b := range data {
			buf[i] = b ^ kb
		}
		score, ratio := scorePrintableASCII(buf)
		outCopy := make([]byte, len(buf))
		copy(outCopy, buf)
		candidates = append(candidates, XORCandidate{
			KeyByte:        kb,
			KeyHex:         fmt.Sprintf("0x%02x", kb),
			Score:          math.Round(score*1000) / 1000,
			PrintableRatio: math.Round(ratio*1000) / 1000,
			OutputUTF8:     safeUTF8Preview(outCopy, 512),
			OutputHex:      hex.EncodeToString(outCopy[:minInt(len(outCopy), 256)]),
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].KeyByte < candidates[j].KeyByte
	})
	return candidates[:topN]
}

// English frequency weights for single-byte XOR scoring.
var asciiCharWeight = func() [256]float64 {
	var w [256]float64
	for i := range w {
		w[i] = -8.0 // non-printable / high bytes strongly penalized
	}
	for c := 0x20; c <= 0x7e; c++ {
		w[c] = 1.5
	}
	w['\n'] = 2.0
	w['\r'] = 1.5
	w['\t'] = 1.5
	w[' '] = 6.5
	freqs := map[byte]float64{
		'e': 6.0, 't': 5.2, 'a': 4.8, 'o': 4.6, 'i': 4.4, 'n': 4.4,
		's': 4.2, 'h': 4.0, 'r': 4.0, 'd': 3.5, 'l': 3.4, 'c': 3.1,
		'u': 3.0, 'm': 2.9, 'w': 2.8, 'f': 2.8, 'g': 2.7, 'y': 2.7,
		'p': 2.7, 'b': 2.6, 'v': 2.4, 'k': 2.3, 'j': 2.0, 'x': 2.0,
		'q': 1.9, 'z': 1.9,
	}
	for ch, sc := range freqs {
		w[ch] = sc
		w[ch-'a'+'A'] = sc * 0.9
	}
	for d := byte('0'); d <= '9'; d++ {
		w[d] = 2.8
	}
	for _, p := range []byte(`.,:;?!-_/"'{}[]()=&@#`) {
		w[p] = 2.2
	}
	return w
}()

func scorePrintableASCII(buf []byte) (float64, float64) {
	if len(buf) == 0 {
		return 0, 0
	}
	var sum float64
	printable := 0
	for _, b := range buf {
		sum += asciiCharWeight[b]
		if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	ratio := float64(printable) / float64(len(buf))
	return (sum / float64(len(buf))) + ratio*2.0, ratio
}

// ─── Hashes (with Custom IVs for MD5 & SHA-256), HMAC, CRC32 ─────────────────

var md5Shift = [64]uint{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

var md5K = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

// MD5WithIV computes RFC 1321 MD5 initialized with custom 4x32-bit state words (A,B,C,D).
func MD5WithIV(data []byte, iv [4]uint32) [16]byte {
	a0, b0, c0, d0 := iv[0], iv[1], iv[2], iv[3]

	origBitLen := uint64(len(data)) * 8
	padLen := (56 - (len(data)+1)%64 + 64) % 64
	padded := make([]byte, len(data)+1+padLen+8)
	copy(padded, data)
	padded[len(data)] = 0x80
	binary.LittleEndian.PutUint64(padded[len(padded)-8:], origBitLen)

	var m [16]uint32
	for off := 0; off < len(padded); off += 64 {
		for j := 0; j < 16; j++ {
			m[j] = binary.LittleEndian.Uint32(padded[off+j*4 : off+j*4+4])
		}
		a, b, c, d := a0, b0, c0, d0
		for i := 0; i < 64; i++ {
			var f uint32
			var g int
			switch {
			case i < 16:
				f = (b & c) | ((^b) & d)
				g = i
			case i < 32:
				f = (d & b) | ((^d) & c)
				g = (5*i + 1) % 16
			case i < 48:
				f = b ^ c ^ d
				g = (3*i + 5) % 16
			default:
				f = c ^ (b | (^d))
				g = (7 * i) % 16
			}
			f = f + a + md5K[i] + m[g]
			a = d
			d = c
			c = b
			b = b + bits.RotateLeft32(f, int(md5Shift[i]))
		}
		a0 += a
		b0 += b
		c0 += c
		d0 += d
	}

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], a0)
	binary.LittleEndian.PutUint32(out[4:8], b0)
	binary.LittleEndian.PutUint32(out[8:12], c0)
	binary.LittleEndian.PutUint32(out[12:16], d0)
	return out
}

// MD5Sum computes MD5 over data, optionally overriding the IV via a 32-hex-char
// string encoding 4 little-endian 32-bit words (matching RFC 1321 standard IV
// "0123456789abcdeffedcba9876543210").
func MD5Sum(data []byte, ivHex string) ([]byte, error) {
	ivHex = cleanHexString(ivHex)
	if ivHex == "" {
		sum := md5.Sum(data)
		return sum[:], nil
	}
	raw, err := hex.DecodeString(ivHex)
	if err != nil || len(raw) != 16 {
		return nil, fmt.Errorf("md5 custom iv_hex must be exactly 16 bytes (32 hex chars, 4x32-bit LE words)")
	}
	iv := [4]uint32{
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint32(raw[4:8]),
		binary.LittleEndian.Uint32(raw[8:12]),
		binary.LittleEndian.Uint32(raw[12:16]),
	}
	sum := MD5WithIV(data, iv)
	return sum[:], nil
}

var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// SHA256WithIV computes FIPS 180-4 SHA-256 initialized with custom 8x32-bit state words (H0..H7).
func SHA256WithIV(data []byte, iv [8]uint32) [32]byte {
	h := iv

	origBitLen := uint64(len(data)) * 8
	padLen := (56 - (len(data)+1)%64 + 64) % 64
	padded := make([]byte, len(data)+1+padLen+8)
	copy(padded, data)
	padded[len(data)] = 0x80
	binary.BigEndian.PutUint64(padded[len(padded)-8:], origBitLen)

	var w [64]uint32
	for off := 0; off < len(padded); off += 64 {
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(padded[off+i*4 : off+i*4+4])
		}
		for i := 16; i < 64; i++ {
			s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ (w[i-15] >> 3)
			s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ (w[i-2] >> 10)
			w[i] = w[i-16] + s0 + w[i-7] + s1
		}

		a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
		for i := 0; i < 64; i++ {
			S1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
			ch := (e & f) ^ ((^e) & g)
			temp1 := hh + S1 + ch + sha256K[i] + w[i]
			S0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := S0 + maj

			hh = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}

		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
		h[5] += f
		h[6] += g
		h[7] += hh
	}

	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:i*4+4], h[i])
	}
	return out
}

// SHA256Sum computes SHA-256 over data, optionally overriding the IV via a 64-hex-char
// string encoding 8 big-endian 32-bit words.
func SHA256Sum(data []byte, ivHex string) ([]byte, error) {
	ivHex = cleanHexString(ivHex)
	if ivHex == "" {
		sum := sha256.Sum256(data)
		return sum[:], nil
	}
	raw, err := hex.DecodeString(ivHex)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("sha256 custom iv_hex must be exactly 32 bytes (64 hex chars, 8x32-bit BE words)")
	}
	var iv [8]uint32
	for i := 0; i < 8; i++ {
		iv[i] = binary.BigEndian.Uint32(raw[i*4 : i*4+4])
	}
	sum := SHA256WithIV(data, iv)
	return sum[:], nil
}

// SHA1Sum returns the SHA-1 digest of data.
func SHA1Sum(data []byte) [20]byte { return sha1.Sum(data) }

// SHA512Sum returns the SHA-512 digest of data.
func SHA512Sum(data []byte) [64]byte { return sha512.Sum512(data) }

// HMACSum computes HMAC using md5, sha1, sha256, or sha512.
func HMACSum(algo string, data, key []byte) ([]byte, error) {
	var fn func() hash.Hash
	switch strings.ToLower(strings.TrimSpace(algo)) {
	case "md5", "hmac_md5":
		fn = md5.New
	case "sha1", "hmac_sha1":
		fn = sha1.New
	case "sha256", "hmac_sha256":
		fn = sha256.New
	case "sha512", "hmac_sha512":
		fn = sha512.New
	default:
		return nil, fmt.Errorf("unsupported hmac algorithm %q", algo)
	}
	mac := hmac.New(fn, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil), nil
}

// CRC32Sum computes a CRC-32 checksum with the chosen polynomial ("ieee", "castagnoli", "koopman").
func CRC32Sum(data []byte, poly string) (uint32, error) {
	switch strings.ToLower(strings.TrimSpace(poly)) {
	case "", "ieee":
		return crc32.ChecksumIEEE(data), nil
	case "castagnoli":
		return crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)), nil
	case "koopman":
		return crc32.Checksum(data, crc32.MakeTable(crc32.Koopman)), nil
	default:
		return 0, fmt.Errorf("unsupported crc32 polynomial %q (want ieee, castagnoli, or koopman)", poly)
	}
}

// ─── Shannon Entropy & Payload Auto-Identifier ───────────────────────────────

// ShannonEntropy returns the Shannon entropy of data in bits per byte (0..8).
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var ent float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return math.Round(ent*10000) / 10000
}

func classifyEntropy(ent float64, byteLen int) string {
	if byteLen == 0 {
		return "empty"
	}
	switch {
	case ent < 3.0:
		return "low"
	case ent < 5.5:
		return "text"
	case ent < 6.8:
		return "encoded"
	default:
		return "high_random_or_encrypted"
	}
}

// IdentifyPayload runs multi-format heuristics over an arbitrary payload string,
// returning detected encodings/magic headers, JWT previews, Shannon entropy, and
// recommended CyberChef pipeline recipes.
func IdentifyPayload(input string) *IdentifyResult {
	trimmed := strings.TrimSpace(input)
	rawBytes := []byte(input)
	ent := ShannonEntropy(rawBytes)

	res := &IdentifyResult{
		InputLen:        len(input),
		DecodedByteLen:  len(rawBytes),
		Entropy:         ent,
		EntropyClass:    classifyEntropy(ent, len(rawBytes)),
		IsPrintableUTF8: isPrintableText(rawBytes),
		Candidates:      []IdentifyCandidate{},
		Recipes:         []RecommendedRecipe{},
	}
	if len(trimmed) == 0 {
		return res
	}

	// 1. JWT detection (header.payload.signature)
	if jwtPrev := tryDetectJWT(trimmed); jwtPrev != nil {
		res.JWT = jwtPrev
		detail := "3-part compact JWS/JWT"
		if jwtPrev.Algorithm != "" {
			detail = fmt.Sprintf("JWT (alg=%s)", jwtPrev.Algorithm)
		}
		res.Candidates = append(res.Candidates, IdentifyCandidate{
			Format:     "jwt",
			Label:      "JSON Web Token (JWT)",
			Confidence: 0.99,
			Details:    detail,
			Preview:    jwtPrev.PayloadJSON,
		})
		parts := strings.Split(trimmed, ".")
		res.Recipes = append(res.Recipes, RecommendedRecipe{
			Name:        "Decode JWT Payload",
			Description: "Base64URL-decode the JWT claims segment",
			Steps: []PipelineStep{
				{Op: "base64_decode", Params: map[string]string{"alphabet": "url", "raw": "true"}},
			},
		})
		_ = parts
	}

	// 2. UUID detection
	if uuidRe.MatchString(trimmed) {
		version := trimmed[14]
		res.Candidates = append(res.Candidates, IdentifyCandidate{
			Format:     "uuid",
			Label:      "UUID",
			Confidence: 0.97,
			Details:    fmt.Sprintf("RFC 4122 UUID (version nibble '%c')", version),
		})
	}

	// 3. JSON detection
	if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
		if json.Valid([]byte(trimmed)) {
			res.Candidates = append(res.Candidates, IdentifyCandidate{
				Format:     "json",
				Label:      "JSON Document",
				Confidence: 0.95,
				Details:    fmt.Sprintf("%d bytes valid JSON", len(trimmed)),
			})
		}
	}

	// 4. URL-encoded detection
	if pctEncodedRe.MatchString(trimmed) {
		if dec, err := url.QueryUnescape(trimmed); err == nil && dec != trimmed {
			res.Candidates = append(res.Candidates, IdentifyCandidate{
				Format:     "url_encoded",
				Label:      "URL Percent-Encoded",
				Confidence: 0.88,
				Details:    fmt.Sprintf("%d percent-escape sequences", len(pctEncodedRe.FindAllString(trimmed, -1))),
				Preview:    safeUTF8Preview([]byte(dec), 160),
			})
			res.Recipes = append(res.Recipes, RecommendedRecipe{
				Name:        "URL Decode",
				Description: "Decode percent-encoded characters",
				Steps:       []PipelineStep{{Op: "url_decode"}},
			})
		}
	}

	// 5. Hex & digest-length detection
	hexClean := cleanHexString(trimmed)
	isHex := len(hexClean) >= 4 && len(hexClean)%2 == 0 && pureHexRe.MatchString(hexClean) && !uuidRe.MatchString(trimmed)
	if isHex {
		decoded, err := hex.DecodeString(hexClean)
		if err == nil && len(decoded) > 0 {
			res.DecodedByteLen = len(decoded)
			hexEnt := ShannonEntropy(decoded)
			res.Entropy = hexEnt
			res.EntropyClass = classifyEntropy(hexEnt, len(decoded))

			switch len(hexClean) {
			case 32:
				res.Candidates = append(res.Candidates, IdentifyCandidate{
					Format:     "md5_digest",
					Label:      "MD5 Digest (or 128-bit Key/Block)",
					Confidence: 0.86,
					Details:    "32 hex chars (16 bytes / 128 bits)",
				})
			case 40:
				res.Candidates = append(res.Candidates, IdentifyCandidate{
					Format:     "sha1_digest",
					Label:      "SHA-1 Digest",
					Confidence: 0.88,
					Details:    "40 hex chars (20 bytes / 160 bits)",
				})
			case 64:
				res.Candidates = append(res.Candidates, IdentifyCandidate{
					Format:     "sha256_digest",
					Label:      "SHA-256 Digest (or 256-bit Key)",
					Confidence: 0.90,
					Details:    "64 hex chars (32 bytes / 256 bits)",
				})
			case 128:
				res.Candidates = append(res.Candidates, IdentifyCandidate{
					Format:     "sha512_digest",
					Label:      "SHA-512 Digest",
					Confidence: 0.90,
					Details:    "128 hex chars (64 bytes / 512 bits)",
				})
			}

			res.Candidates = append(res.Candidates, IdentifyCandidate{
				Format:     "hex",
				Label:      "Hexadecimal",
				Confidence: 0.90,
				Details:    fmt.Sprintf("%d bytes (%d hex chars), entropy %.2f", len(decoded), len(hexClean), hexEnt),
				Preview:    safeUTF8Preview(decoded, 160),
			})
			res.Recipes = append(res.Recipes, RecommendedRecipe{
				Name:        "Hex Decode",
				Description: "Convert hexadecimal text to raw bytes",
				Steps:       []PipelineStep{{Op: "hex_decode"}},
			})

			inspectInnerBinary(res, decoded, "hex_decode", nil)
		}
	}

	// 6. Base64 / Base64URL detection
	if res.JWT == nil {
		if b64Bytes, variant, conf := tryDetectBase64(trimmed, isHex); b64Bytes != nil {
			b64Ent := ShannonEntropy(b64Bytes)
			if !isHex {
				res.DecodedByteLen = len(b64Bytes)
				res.Entropy = b64Ent
				res.EntropyClass = classifyEntropy(b64Ent, len(b64Bytes))
			}
			params := map[string]string{}
			if variant == "url" {
				params["alphabet"] = "url"
			}
			if !strings.Contains(trimmed, "=") {
				params["raw"] = "true"
			}
			label := "Base64"
			if variant == "url" {
				label = "Base64URL"
			}
			res.Candidates = append(res.Candidates, IdentifyCandidate{
				Format:     "base64",
				Label:      label,
				Confidence: conf,
				Details:    fmt.Sprintf("%d decoded bytes, entropy %.2f", len(b64Bytes), b64Ent),
				Preview:    safeUTF8Preview(b64Bytes, 160),
			})
			res.Recipes = append(res.Recipes, RecommendedRecipe{
				Name:        label + " Decode",
				Description: "Decode Base64 payload to raw bytes",
				Steps:       []PipelineStep{{Op: "base64_decode", Params: params}},
			})

			if conf >= 0.7 {
				inspectInnerBinary(res, b64Bytes, "base64_decode", params)
			}
		}
	}

	// 7. Direct raw binary checks (gzip/zlib/protobuf when raw bytes passed directly)
	inspectInnerBinary(res, rawBytes, "", nil)

	// Sort candidates by descending confidence, deterministic tie-break on format.
	sort.Slice(res.Candidates, func(i, j int) bool {
		if res.Candidates[i].Confidence != res.Candidates[j].Confidence {
			return res.Candidates[i].Confidence > res.Candidates[j].Confidence
		}
		return res.Candidates[i].Format < res.Candidates[j].Format
	})

	return res
}

func inspectInnerBinary(res *IdentifyResult, data []byte, outerOp string, outerParams map[string]string) {
	if len(data) < 2 {
		return
	}
	prefixSteps := func(next PipelineStep) []PipelineStep {
		if outerOp == "" {
			return []PipelineStep{next}
		}
		return []PipelineStep{{Op: outerOp, Params: outerParams}, next}
	}
	prefixLabel := ""
	if outerOp != "" {
		prefixLabel = strings.TrimSuffix(outerOp, "_decode") + " -> "
	}

	// Gzip magic: 1f 8b 08
	if len(data) >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08 {
		conf := 0.92
		preview := ""
		details := "Gzip magic header (1f 8b 08)"
		if dec, err := GzipDecompress(data); err == nil {
			conf = 0.98
			details = fmt.Sprintf("Valid Gzip archive -> %d uncompressed bytes", len(dec))
			preview = safeUTF8Preview(dec, 160)
		}
		res.Candidates = append(res.Candidates, IdentifyCandidate{
			Format:     "gzip",
			Label:      "Gzip Compressed Data",
			Confidence: conf,
			Details:    details,
			Preview:    preview,
		})
		res.Recipes = append(res.Recipes, RecommendedRecipe{
			Name:        prefixLabel + "Gzip Decompress",
			Description: "Decompress detected Gzip stream",
			Steps:       prefixSteps(PipelineStep{Op: "gzip_decompress"}),
		})
		return
	}

	// Zlib magic: CMF=0x78 and (CMF*256+FLG)%31 == 0
	if data[0] == 0x78 && (uint16(data[0])*256+uint16(data[1]))%31 == 0 &&
		(data[1] == 0x01 || data[1] == 0x5e || data[1] == 0x9c || data[1] == 0xda) {
		conf := 0.85
		preview := ""
		details := fmt.Sprintf("Zlib magic header (%02x %02x)", data[0], data[1])
		if dec, err := ZlibDecompress(data); err == nil {
			conf = 0.97
			details = fmt.Sprintf("Valid Zlib stream -> %d uncompressed bytes", len(dec))
			preview = safeUTF8Preview(dec, 160)
		}
		res.Candidates = append(res.Candidates, IdentifyCandidate{
			Format:     "zlib",
			Label:      "Zlib Compressed Data",
			Confidence: conf,
			Details:    details,
			Preview:    preview,
		})
		res.Recipes = append(res.Recipes, RecommendedRecipe{
			Name:        prefixLabel + "Zlib Decompress",
			Description: "Decompress detected Zlib stream",
			Steps:       prefixSteps(PipelineStep{Op: "zlib_decompress"}),
		})
		return
	}

	// Protobuf wire candidate (skip if plain text or valid JSON)
	if !json.Valid(data) && !isPrintableText(data) {
		if node, err := DecodeProtobufRaw(data); err == nil && len(node.Fields) > 0 && looksPlausibleProto(node) {
			res.Candidates = append(res.Candidates, IdentifyCandidate{
				Format:     "protobuf",
				Label:      "Protobuf Wire Message",
				Confidence: 0.84,
				Details:    fmt.Sprintf("Parsed %d top-level wire fields (%d bytes)", len(node.Fields), len(data)),
			})
			res.Recipes = append(res.Recipes, RecommendedRecipe{
				Name:        prefixLabel + "Protobuf Wire Decode",
				Description: "Inspect schema-less Protobuf wire fields",
				Steps:       prefixSteps(PipelineStep{Op: "protobuf_decode"}),
			})
		}
	}

	// Block-cipher ciphertext hint (16-byte aligned high-entropy binary)
	if len(data) >= 16 && len(data)%16 == 0 && !isPrintableText(data) && ShannonEntropy(data) >= 6.5 && outerOp != "" {
		res.Candidates = append(res.Candidates, IdentifyCandidate{
			Format:     "block_cipher_candidate",
			Label:      "128-bit Block Cipher Candidate (AES / SM4)",
			Confidence: 0.65,
			Details:    fmt.Sprintf("%d bytes (multiple of 16), high entropy %.2f bits/byte", len(data), ShannonEntropy(data)),
		})
	}
}

func looksPlausibleProto(node *ProtoMessageNode) bool {
	if node == nil || len(node.Fields) == 0 {
		return false
	}
	reasonableFieldNums := 0
	for _, f := range node.Fields {
		if f.FieldNumber >= 1 && f.FieldNumber <= 10000 {
			reasonableFieldNums++
		}
	}
	return float64(reasonableFieldNums)/float64(len(node.Fields)) >= 0.75
}

func tryDetectJWT(s string) *JWTPreview {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil
	}
	if len(parts[0]) < 4 || len(parts[1]) < 2 || len(parts[2]) == 0 {
		return nil
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !json.Valid(hdrBytes) {
		return nil
	}
	payBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !json.Valid(payBytes) {
		return nil
	}
	var hdrMap map[string]any
	if err := json.Unmarshal(hdrBytes, &hdrMap); err != nil {
		return nil
	}
	alg, _ := hdrMap["alg"].(string)
	_, hasTyp := hdrMap["typ"]
	if alg == "" && !hasTyp {
		return nil
	}
	return &JWTPreview{
		HeaderJSON:   prettyOrRawJSON(hdrBytes),
		PayloadJSON:  prettyOrRawJSON(payBytes),
		SignatureB64: parts[2],
		Algorithm:    alg,
	}
}

func tryDetectBase64(s string, alsoHex bool) ([]byte, string, float64) {
	cleaned := stripWhitespace(s)
	if len(cleaned) < 4 || len(cleaned)%4 == 1 {
		return nil, "", 0
	}
	hasURLChars := strings.ContainsAny(cleaned, "-_")
	hasStdChars := strings.ContainsAny(cleaned, "+/")
	if hasURLChars && hasStdChars {
		return nil, "", 0
	}
	variant := "standard"
	enc := base64.StdEncoding
	if hasURLChars {
		variant = "url"
		enc = base64.URLEncoding
	}
	if !strings.Contains(cleaned, "=") {
		enc = enc.WithPadding(base64.NoPadding)
	}
	dec, err := enc.DecodeString(cleaned)
	if err != nil || len(dec) == 0 {
		return nil, "", 0
	}
	// Ensure re-encoding matches to avoid loose matches.
	if strings.TrimRight(enc.EncodeToString(dec), "=") != strings.TrimRight(cleaned, "=") {
		return nil, "", 0
	}
	conf := 0.78
	if strings.HasSuffix(cleaned, "=") || hasStdChars || hasURLChars {
		conf = 0.91
	} else if alsoHex {
		conf = 0.45
	} else if !hasMixedCaseOrDigits(cleaned) {
		// Plain English single word like "password" is technically valid base64!
		conf = 0.35
	}
	return dec, variant, conf
}

func hasMixedCaseOrDigits(s string) bool {
	var lower, upper, digit bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	score := 0
	if lower {
		score++
	}
	if upper {
		score++
	}
	if digit {
		score++
	}
	return score >= 2
}

// ─── Shared Internal Helpers ─────────────────────────────────────────────────

func stripWhitespace(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

func decodeParamBytes(val, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "utf8", "utf-8", "text", "ascii":
		return []byte(val), nil
	case "hex":
		return HexDecode([]byte(val))
	case "base64", "b64":
		return Base64Decode([]byte(val), "", false)
	default:
		return nil, fmt.Errorf("unsupported encoding %q (want utf8, hex, or base64)", encoding)
	}
}

func formatDigestOutput(digest []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "hex":
		return []byte(hex.EncodeToString(digest)), nil
	case "hex_upper":
		return []byte(strings.ToUpper(hex.EncodeToString(digest))), nil
	case "base64", "b64":
		return []byte(base64.StdEncoding.EncodeToString(digest)), nil
	case "raw", "bytes":
		out := make([]byte, len(digest))
		copy(out, digest)
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported output_encoding %q (want hex, hex_upper, base64, or raw)", encoding)
	}
}

func isPrintableText(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) {
		return false
	}
	total, printable := 0, 0
	for _, r := range string(data) {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.95
}

func safeUTF8Preview(data []byte, maxBytes int) string {
	if len(data) == 0 {
		return ""
	}
	truncated := false
	slice := data
	if maxBytes > 0 && len(slice) > maxBytes {
		slice = slice[:maxBytes]
		truncated = true
	}
	var sb strings.Builder
	sb.Grow(len(slice))
	if utf8.Valid(slice) {
		for _, r := range string(slice) {
			if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
				sb.WriteRune(r)
			} else {
				sb.WriteByte('.')
			}
		}
	} else {
		for _, b := range slice {
			if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
	}
	if truncated {
		sb.WriteString("...")
	}
	return sb.String()
}

func prettyOrRawJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err == nil {
		return buf.String()
	}
	return string(raw)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
