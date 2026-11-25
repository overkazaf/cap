package cryptolab

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ─── AES-128 Tables & GF(2^8) Arithmetic for Round-9 DFA ─────────────────────

var aesSBox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var aesInvSBox = func() [256]byte {
	var inv [256]byte
	for i, v := range aesSBox {
		inv[v] = byte(i)
	}
	return inv
}()

var aesRcon = [11]byte{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

// dfaColumnRowIndices maps each Round-9 MixColumns column c (0..3) to the 4
// ciphertext byte positions after Round-10 ShiftRows, ordered by pre-ShiftRows
// row (row 0, row 1, row 2, row 3).
var dfaColumnRowIndices = [4][4]int{
	{0, 13, 10, 7}, // sorted set {0, 7, 10, 13}
	{4, 1, 14, 11}, // sorted set {1, 4, 11, 14}
	{8, 5, 2, 15},  // sorted set {2, 5, 8, 15}
	{12, 9, 6, 3},  // sorted set {3, 6, 9, 12}
}

// dfaColumnSortedIndices are the canonical sorted ShiftRows groups for reporting.
var dfaColumnSortedIndices = [4][4]int{
	{0, 7, 10, 13},
	{1, 4, 11, 14},
	{2, 5, 8, 15},
	{3, 6, 9, 12},
}

// MixColumns coefficients for a single-byte fault at row r (0..3):
// mcFaultCoeffs[r] = [M[0][r], M[1][r], M[2][r], M[3][r]].
var mcFaultCoeffs = [4][4]byte{
	{2, 1, 1, 3},
	{3, 2, 1, 1},
	{1, 3, 2, 1},
	{1, 1, 3, 2},
}

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// Precomputed GF(2^8) multiplication tables for MixColumns and InvMixColumns constants.
var (
	gfMul2  [256]byte
	gfMul3  [256]byte
	gfMul9  [256]byte
	gfMul11 [256]byte
	gfMul13 [256]byte
	gfMul14 [256]byte
)

func init() {
	for i := 0; i < 256; i++ {
		b := byte(i)
		gfMul2[i] = gfMul(b, 2)
		gfMul3[i] = gfMul(b, 3)
		gfMul9[i] = gfMul(b, 9)
		gfMul11[i] = gfMul(b, 11)
		gfMul13[i] = gfMul(b, 13)
		gfMul14[i] = gfMul(b, 14)
	}
}

func gfMulMC(coeff, x byte) byte {
	switch coeff {
	case 1:
		return x
	case 2:
		return gfMul2[x]
	case 3:
		return gfMul3[x]
	default:
		return gfMul(coeff, x)
	}
}

// isSingleBytePreMCFault returns true iff InvMixColumns(d0, d1, d2, d3) has
// Hamming weight exactly 1 (i.e., originated from a single non-zero byte fault
// before Round-9 MixColumns).
func isSingleBytePreMCFault(d0, d1, d2, d3 byte) bool {
	if d0 == 0 && d1 == 0 && d2 == 0 && d3 == 0 {
		return false
	}
	v0 := gfMul14[d0] ^ gfMul11[d1] ^ gfMul13[d2] ^ gfMul9[d3]
	v1 := gfMul9[d0] ^ gfMul14[d1] ^ gfMul11[d2] ^ gfMul13[d3]
	v2 := gfMul13[d0] ^ gfMul9[d1] ^ gfMul14[d2] ^ gfMul11[d3]
	v3 := gfMul11[d0] ^ gfMul13[d1] ^ gfMul9[d2] ^ gfMul14[d3]

	nz := 0
	if v0 != 0 {
		nz++
	}
	if v1 != 0 {
		nz++
	}
	if v2 != 0 {
		nz++
	}
	if v3 != 0 {
		nz++
	}
	return nz == 1
}

// ─── AES-128 Forward/Reverse Key Schedule & Round-9 Fault Simulator ──────────

func aesSubWord(w uint32) uint32 {
	return uint32(aesSBox[w>>24])<<24 |
		uint32(aesSBox[(w>>16)&0xff])<<16 |
		uint32(aesSBox[(w>>8)&0xff])<<8 |
		uint32(aesSBox[w&0xff])
}

func aesRotWord(w uint32) uint32 {
	return (w << 8) | (w >> 24)
}

func expandAES128Key(key [16]byte) [11][16]byte {
	var w [44]uint32
	for i := 0; i < 4; i++ {
		w[i] = binary.BigEndian.Uint32(key[i*4 : i*4+4])
	}
	for i := 4; i < 44; i++ {
		temp := w[i-1]
		if i%4 == 0 {
			temp = aesSubWord(aesRotWord(temp)) ^ (uint32(aesRcon[i/4]) << 24)
		}
		w[i] = w[i-4] ^ temp
	}
	var rks [11][16]byte
	for r := 0; r < 11; r++ {
		for j := 0; j < 4; j++ {
			binary.BigEndian.PutUint32(rks[r][j*4:j*4+4], w[r*4+j])
		}
	}
	return rks
}

// InvertAES128KeySchedule runs the exact AES-128 reverse key schedule from the
// Round-10 subkey K10 back to the 128-bit Master Key K0.
func InvertAES128KeySchedule(k10 [16]byte) [16]byte {
	var w [4]uint32
	for i := 0; i < 4; i++ {
		w[i] = binary.BigEndian.Uint32(k10[i*4 : i*4+4])
	}
	for r := 10; r >= 1; r-- {
		prev3 := w[3] ^ w[2]
		prev2 := w[2] ^ w[1]
		prev1 := w[1] ^ w[0]
		prev0 := w[0] ^ aesSubWord(aesRotWord(prev3)) ^ (uint32(aesRcon[r]) << 24)
		w[0], w[1], w[2], w[3] = prev0, prev1, prev2, prev3
	}
	var k0 [16]byte
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(k0[i*4:i*4+4], w[i])
	}
	return k0
}

func aesAddRoundKey(s *[16]byte, rk *[16]byte) {
	for i := 0; i < 16; i++ {
		s[i] ^= rk[i]
	}
}

func aesSubBytes(s *[16]byte) {
	for i := 0; i < 16; i++ {
		s[i] = aesSBox[s[i]]
	}
}

func aesShiftRows(s *[16]byte) {
	// Row 1: left by 1
	s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
	// Row 2: left by 2
	s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
	// Row 3: left by 3 (right by 1)
	s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
}

func aesMixColumns(s *[16]byte) {
	for c := 0; c < 4; c++ {
		i := c * 4
		a0, a1, a2, a3 := s[i], s[i+1], s[i+2], s[i+3]
		s[i] = gfMul2[a0] ^ gfMul3[a1] ^ a2 ^ a3
		s[i+1] = a0 ^ gfMul2[a1] ^ gfMul3[a2] ^ a3
		s[i+2] = a0 ^ a1 ^ gfMul2[a2] ^ gfMul3[a3]
		s[i+3] = gfMul3[a0] ^ a1 ^ a2 ^ gfMul2[a3]
	}
}

func aes128EncryptWithOptionalR9Fault(rks *[11][16]byte, pt [16]byte, inject bool, faultIdx int, faultXOR byte) [16]byte {
	s := pt
	aesAddRoundKey(&s, &rks[0])
	for r := 1; r <= 9; r++ {
		aesSubBytes(&s)
		aesShiftRows(&s)
		if r == 9 && inject {
			s[faultIdx] ^= faultXOR
		}
		aesMixColumns(&s)
		aesAddRoundKey(&s, &rks[r])
	}
	aesSubBytes(&s)
	aesShiftRows(&s)
	aesAddRoundKey(&s, &rks[10])
	return s
}

// SimulateAES128Round9Fault computes both the valid AES-128 ciphertext and the
// faulty ciphertext produced by XORing state[faultByteIdx%16] with faultXOR
// immediately before Round-9 MixColumns.
func SimulateAES128Round9Fault(key, plaintext [16]byte, faultByteIdx int, faultXOR byte) (validCT, faultyCT [16]byte) {
	rks := expandAES128Key(key)
	idx := ((faultByteIdx % 16) + 16) % 16
	validCT = aes128EncryptWithOptionalR9Fault(&rks, plaintext, false, 0, 0)
	faultyCT = aes128EncryptWithOptionalR9Fault(&rks, plaintext, true, idx, faultXOR)
	return validCT, faultyCT
}

// ─── White-Box AES-128 Round-9 DFA Solver (Piret-Quisquater / PhoenixAES) ────

// SolveAES128DFA recovers the AES-128 Round-10 subkey K10 and Master Key K0 from
// a valid 16-byte ciphertext and faulty ciphertexts induced by single-byte faults
// before Round-9 MixColumns (typically 2 faults per ShiftRows column = 8 total).
func SolveAES128DFA(req DFARequest) (*DFAResult, error) {
	start := time.Now()
	validBytes, err := parseFixed16Hex(req.ValidCiphertextHex, "valid_ciphertext_hex")
	if err != nil {
		return nil, err
	}

	res := &DFAResult{
		ValidCiphertextHex: hex.EncodeToString(validBytes[:]),
		TotalFaultsInput:   len(req.FaultyCiphertextsHex),
		Notes:              []string{},
	}
	for g := 0; g < 4; g++ {
		res.Columns[g] = DFAColumnStatus{
			GroupIndex:  g,
			ByteIndices: dfaColumnSortedIndices[g],
		}
	}

	if len(req.FaultyCiphertextsHex) == 0 {
		res.Notes = append(res.Notes, "No faulty ciphertexts provided; supply at least 2 Round-9 faults per ShiftRows column (8 total).")
		res.ElapsedUS = time.Since(start).Microseconds()
		return res, nil
	}

	var grouped [4][][16]byte
	seenFault := make(map[[16]byte]struct{}, len(req.FaultyCiphertextsHex))

	for i, fHex := range req.FaultyCiphertextsHex {
		if strings.TrimSpace(fHex) == "" {
			continue
		}
		fb, err := parseFixed16Hex(fHex, fmt.Sprintf("faulty_ciphertexts_hex[%d]", i))
		if err != nil {
			return nil, err
		}
		if fb == validBytes {
			res.IgnoredFaults++
			res.Notes = append(res.Notes, fmt.Sprintf("Fault #%d is identical to valid ciphertext (ignored).", i))
			continue
		}
		if _, dup := seenFault[fb]; dup {
			res.IgnoredFaults++
			continue
		}
		seenFault[fb] = struct{}{}

		groupIdx, diffCount := classifyFaultColumn(validBytes, fb)
		if groupIdx < 0 {
			res.IgnoredFaults++
			res.Notes = append(res.Notes, fmt.Sprintf("Fault #%d differs in %d bytes not matching any Round-9 ShiftRows column group (ignored).", i, diffCount))
			continue
		}
		grouped[groupIdx] = append(grouped[groupIdx], fb)
		res.UsableFaults++
	}

	var k10 [16]byte
	allSolved := true

	for g := 0; g < 4; g++ {
		colFaults := grouped[g]
		res.Columns[g].FaultCount = len(colFaults)
		if len(colFaults) == 0 {
			allSolved = false
			res.Notes = append(res.Notes, fmt.Sprintf("Column group %d %v has 0 faults; inject at least 2 faults affecting this column.", g, dfaColumnSortedIndices[g]))
			continue
		}

		cands := solveColumnGroup(validBytes, colFaults, dfaColumnRowIndices[g])
		res.Columns[g].CandidateCount = len(cands)

		if len(cands) == 1 {
			tuple := cands[0]
			rowIdx := dfaColumnRowIndices[g]
			k10[rowIdx[0]] = byte(tuple >> 24)
			k10[rowIdx[1]] = byte(tuple >> 16)
			k10[rowIdx[2]] = byte(tuple >> 8)
			k10[rowIdx[3]] = byte(tuple)
			res.Columns[g].Solved = true
			sortedIdx := dfaColumnSortedIndices[g]
			sub := [4]byte{k10[sortedIdx[0]], k10[sortedIdx[1]], k10[sortedIdx[2]], k10[sortedIdx[3]]}
			res.Columns[g].SubkeyBytesHex = hex.EncodeToString(sub[:])
		} else {
			allSolved = false
			if len(cands) == 0 {
				res.Notes = append(res.Notes, fmt.Sprintf("Column group %d %v has 0 valid candidates — verify faults were single-byte before Round-9 MixColumns (not Round-8 or multi-byte).", g, dfaColumnSortedIndices[g]))
			} else {
				res.Notes = append(res.Notes, fmt.Sprintf("Column group %d %v narrowed to %d candidates from %d fault(s); supply 1 more fault in this column.", g, dfaColumnSortedIndices[g], len(cands), len(colFaults)))
			}
		}
	}

	if allSolved {
		k0 := InvertAES128KeySchedule(k10)
		res.Solved = true
		res.Round10KeyHex = hex.EncodeToString(k10[:])
		res.MasterKeyHex = hex.EncodeToString(k0[:])

		if strings.TrimSpace(req.PlaintextHex) != "" {
			pt, err := parseFixed16Hex(req.PlaintextHex, "plaintext_hex")
			if err != nil {
				return nil, err
			}
			block, _ := aes.NewCipher(k0[:])
			var checkCT [16]byte
			block.Encrypt(checkCT[:], pt[:])
			if checkCT == validBytes {
				res.VerifiedWithPlaintext = true
				res.Notes = append(res.Notes, "Recovered Master Key verified against supplied plaintext/ciphertext pair via AES-128.")
			} else {
				res.Notes = append(res.Notes, "Warning: recovered Master Key did NOT encrypt plaintext_hex to valid_ciphertext_hex (check plaintext/mode/IV or external encodings).")
			}
		}
	}

	res.ElapsedUS = time.Since(start).Microseconds()
	return res, nil
}

func classifyFaultColumn(valid, faulty [16]byte) (groupIdx int, diffCount int) {
	var diffMask uint16
	for i := 0; i < 16; i++ {
		if valid[i] != faulty[i] {
			diffMask |= 1 << uint(i)
			diffCount++
		}
	}
	if diffCount != 4 {
		return -1, diffCount
	}
	for g := 0; g < 4; g++ {
		var targetMask uint16
		for _, idx := range dfaColumnSortedIndices[g] {
			targetMask |= 1 << uint(idx)
		}
		if diffMask == targetMask {
			return g, diffCount
		}
	}
	return -1, diffCount
}

// solveColumnGroup finds all 4-byte K10 tuples (packed as big-endian uint32 in
// rowIdx order [row0, row1, row2, row3]) consistent with every faulty ciphertext
// in colFaults.
func solveColumnGroup(valid [16]byte, colFaults [][16]byte, rowIdx [4]int) []uint32 {
	if len(colFaults) == 0 {
		return nil
	}

	// Step 1: Enumerate all candidates satisfying fault #0 by factoring through
	// (row r in 0..3, fault byte f in 1..255) — only 1,020 combinations instead of 2^32.
	f0 := colFaults[0]
	var byDelta [4][256][]byte
	for j := 0; j < 4; j++ {
		cv := valid[rowIdx[j]]
		cf := f0[rowIdx[j]]
		for k := 0; k < 256; k++ {
			kb := byte(k)
			d := aesInvSBox[cv^kb] ^ aesInvSBox[cf^kb]
			byDelta[j][d] = append(byDelta[j][d], kb)
		}
	}

	candSet := make(map[uint32]struct{}, 1536)
	for r := 0; r < 4; r++ {
		coeffs := mcFaultCoeffs[r]
		for f := 1; f < 256; f++ {
			fb := byte(f)
			ks0 := byDelta[0][gfMulMC(coeffs[0], fb)]
			if len(ks0) == 0 {
				continue
			}
			ks1 := byDelta[1][gfMulMC(coeffs[1], fb)]
			if len(ks1) == 0 {
				continue
			}
			ks2 := byDelta[2][gfMulMC(coeffs[2], fb)]
			if len(ks2) == 0 {
				continue
			}
			ks3 := byDelta[3][gfMulMC(coeffs[3], fb)]
			if len(ks3) == 0 {
				continue
			}
			for _, k0 := range ks0 {
				u0 := uint32(k0) << 24
				for _, k1 := range ks1 {
					u1 := u0 | (uint32(k1) << 16)
					for _, k2 := range ks2 {
						u2 := u1 | (uint32(k2) << 8)
						for _, k3 := range ks3 {
							candSet[u2|uint32(k3)] = struct{}{}
						}
					}
				}
			}
		}
	}

	cands := make([]uint32, 0, len(candSet))
	for tuple := range candSet {
		cands = append(cands, tuple)
	}

	// Step 2: Intersect with each subsequent fault using O(1) InvMixColumns check.
	for fi := 1; fi < len(colFaults) && len(cands) > 0; fi++ {
		ff := colFaults[fi]
		cv0, cv1, cv2, cv3 := valid[rowIdx[0]], valid[rowIdx[1]], valid[rowIdx[2]], valid[rowIdx[3]]
		cf0, cf1, cf2, cf3 := ff[rowIdx[0]], ff[rowIdx[1]], ff[rowIdx[2]], ff[rowIdx[3]]

		next := cands[:0]
		for _, tuple := range cands {
			k0 := byte(tuple >> 24)
			k1 := byte(tuple >> 16)
			k2 := byte(tuple >> 8)
			k3 := byte(tuple)

			d0 := aesInvSBox[cv0^k0] ^ aesInvSBox[cf0^k0]
			d1 := aesInvSBox[cv1^k1] ^ aesInvSBox[cf1^k1]
			d2 := aesInvSBox[cv2^k2] ^ aesInvSBox[cf2^k2]
			d3 := aesInvSBox[cv3^k3] ^ aesInvSBox[cf3^k3]

			if isSingleBytePreMCFault(d0, d1, d2, d3) {
				next = append(next, tuple)
			}
		}
		cands = next
	}

	return cands
}

func parseFixed16Hex(s, fieldName string) ([16]byte, error) {
	var out [16]byte
	raw, err := HexDecode([]byte(s))
	if err != nil {
		return out, fmt.Errorf("dfa %s: %w", fieldName, err)
	}
	if len(raw) != 16 {
		return out, fmt.Errorf("dfa %s must be exactly 16 bytes (32 hex chars), got %d bytes", fieldName, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// ─── Fault-Injection Script Generators (Unidbg Java & Qiling Python) ─────────

var dfaJavaIdentRe = regexp.MustCompile(`[^A-Za-z0-9_]`)

// GenerateDFAFaultScript builds a ready-to-run Unidbg (Java) or Qiling (Python)
// Round-9 White-Box AES fault-injection script that captures the baseline
// ciphertext, sweeps single-byte XOR faults over the 16-byte state buffer, and
// emits [CAP_RE] {"kind":"dfa_pair",...} JSON records for SolveAES128DFA.
func GenerateDFAFaultScript(engine string, cfg DFAScriptConfig) *GeneratedDFAScript {
	eng := strings.ToLower(strings.TrimSpace(engine))
	if eng == "java" || eng == "unidbg" {
		return generateUnidbgDFAScript(cfg)
	}
	return generateQilingDFAScript(cfg)
}

func normalizedDFAConfig(cfg DFAScriptConfig) DFAScriptConfig {
	out := cfg
	if strings.TrimSpace(out.BinaryPath) == "" {
		out.BinaryPath = "/path/to/libwbaes.so"
	}
	if strings.TrimSpace(out.APKPath) == "" {
		out.APKPath = "/path/to/app.apk"
	}
	if strings.TrimSpace(out.PackageName) == "" {
		out.PackageName = "com.example.wbaes"
	}
	switch strings.ToLower(strings.TrimSpace(out.Arch)) {
	case "arm", "armv7", "arm32":
		out.Arch = "arm"
	case "x86_64", "amd64":
		out.Arch = "x86_64"
	default:
		out.Arch = "arm64"
	}
	if strings.TrimSpace(out.RootFS) == "" {
		switch out.Arch {
		case "arm":
			out.RootFS = "/path/to/qiling/rootfs/arm_linux"
		case "x86_64":
			out.RootFS = "/path/to/qiling/rootfs/x8664_linux"
		default:
			out.RootFS = "/path/to/qiling/rootfs/arm64_linux"
		}
	}
	if strings.TrimSpace(out.TargetClass) == "" {
		out.TargetClass = strings.ReplaceAll(out.PackageName, ".", "/") + "/WhiteBoxAES"
	}
	if strings.TrimSpace(out.TargetMethod) == "" {
		out.TargetMethod = "encryptBlock"
	}
	if strings.TrimSpace(out.MethodSignature) == "" {
		out.MethodSignature = "([B)[B"
	}
	if strings.TrimSpace(out.TargetSymbol) == "" {
		out.TargetSymbol = "wb_aes_encrypt"
	}
	if strings.TrimSpace(out.TargetAddr) == "" {
		out.TargetAddr = "0x1000"
	}
	if strings.TrimSpace(out.FaultHookAddr) == "" {
		out.FaultHookAddr = "0x1480"
	}
	if strings.TrimSpace(out.StateBufReg) == "" {
		switch out.Arch {
		case "arm":
			out.StateBufReg = "r0"
		case "x86_64":
			out.StateBufReg = "rdi"
		default:
			out.StateBufReg = "x0"
		}
	}
	if strings.TrimSpace(out.PlaintextHex) == "" {
		out.PlaintextHex = "00112233445566778899aabbccddeeff"
	}
	if out.FaultXOR == 0 {
		out.FaultXOR = 0x01
	}
	if out.FaultsPerByte <= 0 {
		out.FaultsPerByte = 2
	}
	if out.FaultsPerByte > 8 {
		out.FaultsPerByte = 8
	}
	if strings.TrimSpace(out.ClassName) == "" {
		out.ClassName = "CapWbAesDfaHarness"
	} else {
		cleaned := dfaJavaIdentRe.ReplaceAllString(out.ClassName, "")
		if cleaned == "" || (cleaned[0] >= '0' && cleaned[0] <= '9') {
			cleaned = "CapWbAesDfaHarness"
		}
		out.ClassName = cleaned
	}
	return out
}

func dfaFaultMasks(base byte, count int) []byte {
	pool := []byte{base, base ^ 0x55, base ^ 0xaa, base ^ 0xff, 0x3c, 0xc3, 0x0f, 0xf0}
	seen := map[byte]bool{0: true}
	var out []byte
	for _, m := range pool {
		if len(out) >= count {
			break
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	for b := byte(1); len(out) < count; b++ {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out
}

func generateQilingDFAScript(rawCfg DFAScriptConfig) *GeneratedDFAScript {
	cfg := normalizedDFAConfig(rawCfg)
	masks := dfaFaultMasks(cfg.FaultXOR, cfg.FaultsPerByte)
	maskStrs := make([]string, len(masks))
	for i, m := range masks {
		maskStrs[i] = fmt.Sprintf("0x%02x", m)
	}

	var regSetup string
	switch cfg.Arch {
	case "arm":
		regSetup = `    ql.arch.regs.r0 = in_addr
    ql.arch.regs.r1 = out_addr
    ql.arch.regs.r2 = 16
    ql.arch.regs.lr = stop_addr`
	case "x86_64":
		regSetup = `    ql.arch.regs.rdi = in_addr
    ql.arch.regs.rsi = out_addr
    ql.arch.regs.rdx = 16
    ql.stack_push(stop_addr)`
	default:
		regSetup = `    ql.arch.regs.x0 = in_addr
    ql.arch.regs.x1 = out_addr
    ql.arch.regs.x2 = 16
    ql.arch.regs.lr = stop_addr`
	}

	code := fmt.Sprintf(`#!/usr/bin/env python3
"""cap Auto-Generated Qiling White-Box AES-128 Round-9 DFA Fault Collector (%s)."""

import json
import os
from qiling import Qiling
from qiling.const import QL_VERBOSE

BINARY_PATH = os.environ.get("CAP_RE_BINARY") or %s
ROOTFS = os.environ.get("CAP_RE_ROOTFS") or %s
TARGET_SYMBOL = os.environ.get("CAP_RE_SYMBOL") or %s
TARGET_ADDR_STR = os.environ.get("CAP_RE_TARGET_ADDR") or %s
FAULT_HOOK_ADDR_STR = os.environ.get("CAP_DFA_FAULT_ADDR") or %s
STATE_BUF_REG = os.environ.get("CAP_DFA_STATE_REG") or %s
STATE_BUF_ADDR_STR = os.environ.get("CAP_DFA_STATE_ADDR") or %s
PLAINTEXT_HEX = os.environ.get("CAP_DFA_PLAINTEXT_HEX") or %s
FAULT_MASKS = [%s]


def emit(kind: str, **payload):
    print("[CAP_RE] " + json.dumps({"kind": kind, **payload}, ensure_ascii=False), flush=True)


def resolve_addr(base: int, addr_str: str) -> int:
    val = int(addr_str, 0) if addr_str else 0
    if val == 0:
        return 0
    return base + val if val < base else val


def run_once(ql_factory, plaintext: bytes, fault_byte_idx=None, fault_xor: int = 0) -> bytes:
    ql = ql_factory()
    base = ql.loader.load_address
    entry_addr = resolve_addr(base, TARGET_ADDR_STR)
    fault_addr = resolve_addr(base, FAULT_HOOK_ADDR_STR)
    fixed_state_addr = resolve_addr(base, STATE_BUF_ADDR_STR) if STATE_BUF_ADDR_STR else 0

    scratch_base = 0x50000000
    ql.mem.map(scratch_base, 0x4000, info="[cap_dfa_scratch]")
    in_addr = scratch_base + 0x100
    out_addr = scratch_base + 0x1000
    stop_addr = scratch_base + 0x3F00

    ql.mem.write(in_addr, plaintext)
    ql.mem.write(out_addr, b"\x00" * 16)
    ql.mem.write(stop_addr, b"\x00" * 16)

%s

    injected = {"done": False}

    if fault_byte_idx is not None and fault_addr != 0:
        def inject_fault(ql_inst):
            if injected["done"]:
                return
            injected["done"] = True
            buf_ptr = fixed_state_addr if fixed_state_addr != 0 else ql_inst.arch.regs.read(STATE_BUF_REG)
            orig = ql_inst.mem.read(buf_ptr + fault_byte_idx, 1)
            mutated = bytes([orig[0] ^ fault_xor])
            ql_inst.mem.write(buf_ptr + fault_byte_idx, mutated)

        ql.hook_address(inject_fault, fault_addr)

    ql.run(begin=entry_addr, end=stop_addr)
    return bytes(ql.mem.read(out_addr, 16))


def main():
    if not os.path.isfile(BINARY_PATH):
        raise FileNotFoundError(f"Target binary not found: {BINARY_PATH}")
    if not os.path.isdir(ROOTFS):
        raise FileNotFoundError(f"Qiling rootfs not found: {ROOTFS}")

    plaintext = bytes.fromhex(PLAINTEXT_HEX)
    if len(plaintext) != 16:
        raise ValueError("PLAINTEXT_HEX must be exactly 16 bytes (32 hex chars)")

    def make_ql():
        return Qiling([BINARY_PATH], ROOTFS, verbose=QL_VERBOSE.OFF)

    emit("info", stage="baseline", binary=BINARY_PATH, symbol=TARGET_SYMBOL, fault_addr=FAULT_HOOK_ADDR_STR)
    valid_ct = run_once(make_ql, plaintext)
    valid_hex = valid_ct.hex()
    emit("dfa_baseline", plaintext_hex=plaintext.hex(), valid_ciphertext_hex=valid_hex)

    faulty_list = []
    # Sweep 4 ShiftRows columns (bytes 0, 4, 8, 12 hit columns 0..3; full 0..15 sweep guarantees coverage).
    for byte_idx in range(16):
        for xor_val in FAULT_MASKS:
            faulty_ct = run_once(make_ql, plaintext, fault_byte_idx=byte_idx, fault_xor=xor_val)
            faulty_hex = faulty_ct.hex()
            if faulty_hex != valid_hex:
                faulty_list.append(faulty_hex)
                emit(
                    "dfa_pair",
                    byte_index=byte_idx,
                    fault_xor=hex(xor_val),
                    valid_ciphertext_hex=valid_hex,
                    faulty_ciphertext_hex=faulty_hex,
                )

    emit(
        "dfa_bundle",
        plaintext_hex=plaintext.hex(),
        valid_ciphertext_hex=valid_hex,
        faulty_ciphertexts_hex=faulty_list,
    )


if __name__ == "__main__":
    main()
`,
		cfg.Arch,
		jsonQuote(cfg.BinaryPath),
		jsonQuote(cfg.RootFS),
		jsonQuote(cfg.TargetSymbol),
		jsonQuote(cfg.TargetAddr),
		jsonQuote(cfg.FaultHookAddr),
		jsonQuote(cfg.StateBufReg),
		jsonQuote(cfg.StateBufAddr),
		jsonQuote(cfg.PlaintextHex),
		strings.Join(maskStrs, ", "),
		regSetup,
	)

	return &GeneratedDFAScript{
		Engine:      "qiling",
		Language:    "python",
		FileName:    "wbaes_dfa_qiling.py",
		Title:       fmt.Sprintf("Qiling %s White-Box AES-128 DFA Collector", strings.ToUpper(cfg.Arch)),
		Description: fmt.Sprintf("Captures baseline ciphertext and sweeps Round-9 single-byte state faults in %s, emitting [CAP_RE] dfa_pair JSON.", filepath.Base(cfg.BinaryPath)),
		Code:        code,
		Notes: []string{
			"Point CAP_DFA_FAULT_ADDR to an instruction right before Round-9 MixColumns (between Round-8 MixColumns and Round-9 MixColumns).",
			"Set CAP_DFA_STATE_REG (or CAP_DFA_STATE_ADDR) to the register/address pointing to the 16-byte AES state buffer.",
			"Feed the emitted valid_ciphertext_hex and faulty_ciphertexts_hex directly into SolveAES128DFA.",
		},
	}
}

func generateUnidbgDFAScript(rawCfg DFAScriptConfig) *GeneratedDFAScript {
	cfg := normalizedDFAConfig(rawCfg)
	masks := dfaFaultMasks(cfg.FaultXOR, cfg.FaultsPerByte)
	maskStrs := make([]string, len(masks))
	for i, m := range masks {
		maskStrs[i] = fmt.Sprintf("(byte) 0x%02x", m)
	}

	builderCall := "AndroidEmulatorBuilder.for64Bit()"
	regImport := "unicorn.Arm64Const;"
	if cfg.Arch == "arm" {
		builderCall = "AndroidEmulatorBuilder.for32Bit()"
		regImport = "unicorn.ArmConst;"
	}
	regConst := unidbgRegConst(cfg.Arch, cfg.StateBufReg)
	methodAndSig := cfg.TargetMethod + cfg.MethodSignature

	code := fmt.Sprintf(`// ─── cap Auto-Generated Unidbg White-Box AES-128 Round-9 DFA Collector ────
// Library: %s
// Target:  %s -> %s
// Hook:    %s (register %s)

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import %s

public class %s extends AbstractJni {
    private static final String PROCESS_NAME = %s;
    private static final String APK_PATH = envOr("CAP_RE_APK", %s);
    private static final String SO_PATH = envOr("CAP_RE_BINARY", %s);
    private static final String TARGET_CLASS = %s;
    private static final String TARGET_METHOD_SIG = %s;
    private static final long FAULT_HOOK_OFFSET = Long.decode(envOr("CAP_DFA_FAULT_ADDR", %s));
    private static final long STATIC_STATE_ADDR = parseOptionalLong(envOr("CAP_DFA_STATE_ADDR", %s));
    private static final String PLAINTEXT_HEX = envOr("CAP_DFA_PLAINTEXT_HEX", %s);
    private static final byte[] FAULT_MASKS = new byte[] { %s };

    private final AndroidEmulator emulator;
    private final VM vm;
    private final DalvikModule dm;
    private final Module module;
    private final DvmClass targetClass;

    private volatile int activeFaultByte = -1;
    private volatile byte activeFaultXor = 0;
    private volatile boolean faultInjectedInRun = false;

    public %s() {
        this.emulator = %s.setProcessName(PROCESS_NAME).build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        File apkFile = new File(APK_PATH);
        this.vm = apkFile.isFile() ? emulator.createDalvikVM(apkFile) : emulator.createDalvikVM();
        this.vm.setVerbose(false);
        this.vm.setJni(this);

        File soFile = new File(SO_PATH);
        this.dm = this.vm.loadLibrary(soFile, true);
        this.module = this.dm.getModule();
        this.dm.callJNI_OnLoad(emulator);
        this.targetClass = this.vm.resolveClass(TARGET_CLASS);

        installFaultHook();
    }

    private void installFaultHook() {
        long hookAddr = module.base + FAULT_HOOK_OFFSET;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (activeFaultByte < 0 || faultInjectedInRun) {
                    return;
                }
                faultInjectedInRun = true;
                long statePtr = STATIC_STATE_ADDR != 0L
                        ? STATIC_STATE_ADDR
                        : backend.reg_read(%s).longValue();
                byte[] cur = backend.mem_read(statePtr + activeFaultByte, 1);
                cur[0] = (byte) (cur[0] ^ activeFaultXor);
                backend.mem_write(statePtr + activeFaultByte, cur);
            }

            @Override
            public void onAttach(UnHook unHook) { }

            @Override
            public void detach() { }
        }, hookAddr, hookAddr + 4, null);
    }

    public String invokeOnce(byte[] plaintext, int faultByteIdx, byte faultXor) {
        this.activeFaultByte = faultByteIdx;
        this.activeFaultXor = faultXor;
        this.faultInjectedInRun = false;
        DvmObject<?> ret = targetClass.callStaticJniMethodObject(
                emulator,
                TARGET_METHOD_SIG,
                new ByteArray(vm, plaintext)
        );
        this.activeFaultByte = -1;
        if (ret == null || ret.getValue() == null) {
            return "";
        }
        Object val = ret.getValue();
        if (val instanceof byte[]) {
            return bytesToHex((byte[]) val);
        }
        return String.valueOf(val);
    }

    public void sweepAndEmit() {
        byte[] pt = hexToBytes(PLAINTEXT_HEX);
        String validHex = invokeOnce(pt, -1, (byte) 0);
        System.out.println("[CAP_RE] {\"kind\":\"dfa_baseline\",\"plaintext_hex\":\"" + PLAINTEXT_HEX + "\",\"valid_ciphertext_hex\":\"" + validHex + "\"}");

        List<String> faultyList = new ArrayList<>();
        for (int byteIdx = 0; byteIdx < 16; byteIdx++) {
            for (byte mask : FAULT_MASKS) {
                String faultyHex = invokeOnce(pt, byteIdx, mask);
                if (!faultyHex.isEmpty() && !faultyHex.equalsIgnoreCase(validHex)) {
                    faultyList.add(faultyHex);
                    System.out.printf(
                            "[CAP_RE] {\"kind\":\"dfa_pair\",\"byte_index\":%%d,\"fault_xor\":\"0x%%02x\",\"valid_ciphertext_hex\":\"%%s\",\"faulty_ciphertext_hex\":\"%%s\"}%%n",
                            byteIdx, mask & 0xff, validHex, faultyHex
                    );
                }
            }
        }
        System.out.println("[CAP_RE] {\"kind\":\"dfa_summary\",\"valid_ciphertext_hex\":\"" + validHex + "\",\"fault_count\":" + faultyList.size() + "}");
    }

    public void close() throws IOException {
        emulator.close();
    }

    private static String envOr(String key, String fallback) {
        String v = System.getenv(key);
        return (v != null && !v.trim().isEmpty()) ? v.trim() : fallback;
    }

    private static long parseOptionalLong(String s) {
        if (s == null || s.trim().isEmpty()) return 0L;
        return Long.decode(s.trim());
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        %s harness = new %s();
        try {
            harness.sweepAndEmit();
        } finally {
            harness.close();
        }
    }
}
`,
		stripLineBreaks(cfg.BinaryPath),
		stripLineBreaks(cfg.TargetClass), stripLineBreaks(methodAndSig),
		stripLineBreaks(cfg.FaultHookAddr), stripLineBreaks(cfg.StateBufReg),
		regImport,
		cfg.ClassName,
		jsonQuote(cfg.PackageName),
		jsonQuote(cfg.APKPath),
		jsonQuote(cfg.BinaryPath),
		jsonQuote(cfg.TargetClass),
		jsonQuote(methodAndSig),
		jsonQuote(cfg.FaultHookAddr),
		jsonQuote(cfg.StateBufAddr),
		jsonQuote(cfg.PlaintextHex),
		strings.Join(maskStrs, ", "),
		cfg.ClassName,
		builderCall,
		regConst,
		cfg.ClassName,
		cfg.ClassName,
	)

	return &GeneratedDFAScript{
		Engine:      "unidbg",
		Language:    "java",
		FileName:    cfg.ClassName + ".java",
		Title:       fmt.Sprintf("Unidbg %s White-Box AES-128 DFA Collector", strings.ToUpper(cfg.Arch)),
		Description: fmt.Sprintf("Unidbg JNI harness hooking %s+%s to sweep Round-9 single-byte state faults and emit [CAP_RE] dfa_pair JSON.", filepath.Base(cfg.BinaryPath), cfg.FaultHookAddr),
		Code:        code,
		Notes: []string{
			fmt.Sprintf("Verify FAULT_HOOK_OFFSET (%s) executes between Round-8 MixColumns and Round-9 MixColumns.", cfg.FaultHookAddr),
			"Adjust the register constant if the 16-byte AES state buffer lives in a register other than X0/R0 (or set CAP_DFA_STATE_ADDR).",
			"Pipe emitted [CAP_RE] dfa_pair JSON ciphertexts into SolveAES128DFA to recover the 128-bit master key.",
		},
	}
}

func unidbgRegConst(arch, reg string) string {
	r := strings.ToUpper(strings.TrimSpace(reg))
	if arch == "arm" {
		switch r {
		case "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "SP", "LR":
			return "ArmConst.UC_ARM_REG_" + r
		default:
			return "ArmConst.UC_ARM_REG_R0"
		}
	}
	if strings.HasPrefix(r, "X") && len(r) >= 2 && len(r) <= 3 {
		valid := true
		for i := 1; i < len(r); i++ {
			if r[i] < '0' || r[i] > '9' {
				valid = false
			}
		}
		if valid {
			return "Arm64Const.UC_ARM64_REG_" + r
		}
	}
	if r == "SP" || r == "LR" {
		return "Arm64Const.UC_ARM64_REG_" + r
	}
	return "Arm64Const.UC_ARM64_REG_X0"
}

func stripLineBreaks(s string) string {
	r := strings.NewReplacer("\r", " ", "\n", " ")
	return r.Replace(s)
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
