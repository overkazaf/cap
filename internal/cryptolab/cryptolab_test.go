package cryptolab

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ─── 1. SM4 Official GB/T 32907-2016 Test Vectors ────────────────────────────

func TestSM4OfficialVectors(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	pt, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	wantSingle := "681edf34d206965e86b3e94f536e4246"
	wantMillion := "595298c7c6fd271f0402f804c33d3f66"

	blk, err := NewSM4Cipher(key)
	if err != nil {
		t.Fatalf("NewSM4Cipher failed: %v", err)
	}

	var ct [16]byte
	blk.Encrypt(ct[:], pt)
	if got := hex.EncodeToString(ct[:]); got != wantSingle {
		t.Fatalf("SM4 single-block vector mismatch:\ngot:  %s\nwant: %s", got, wantSingle)
	}

	var dec [16]byte
	blk.Decrypt(dec[:], ct[:])
	if !bytes.Equal(dec[:], pt) {
		t.Fatalf("SM4 single-block decrypt mismatch: got %x want %x", dec, pt)
	}

	// Official GB/T 32907-2016 Appendix A.2: 1,000,000 iterative encryptions.
	var state [16]byte
	copy(state[:], pt)
	for i := 0; i < 1_000_000; i++ {
		blk.Encrypt(state[:], state[:])
	}
	if got := hex.EncodeToString(state[:]); got != wantMillion {
		t.Fatalf("SM4 1,000,000-round vector mismatch:\ngot:  %s\nwant: %s", got, wantMillion)
	}
}

func TestSM4ModesAndPaddings(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("fedcba98765432100123456789abcdef")

	cases := []struct {
		mode    string
		padding string
		pt      []byte
	}{
		{"ecb", "pkcs7", []byte("Hello SM4 ECB PKCS7!")},
		{"ecb", "zero", []byte("Hello SM4 Zero")},
		{"ecb", "none", []byte("0123456789abcdef")},
		{"cbc", "pkcs7", []byte("Multi-block SM4 CBC message testing chaining across blocks 1234567890")},
		{"cbc", "zero", []byte("SM4 CBC zero padding")},
		{"cbc", "none", []byte("0123456789abcdef0123456789abcdef")},
		{"ctr", "none", []byte("Stream mode SM4 CTR arbitrary length 17b!")},
	}

	for _, tc := range cases {
		ct, err := SM4Encrypt(tc.pt, key, iv, tc.mode, tc.padding)
		if err != nil {
			t.Fatalf("SM4Encrypt(%s/%s) failed: %v", tc.mode, tc.padding, err)
		}
		got, err := SM4Decrypt(ct, key, iv, tc.mode, tc.padding)
		if err != nil {
			t.Fatalf("SM4Decrypt(%s/%s) failed: %v", tc.mode, tc.padding, err)
		}
		if !bytes.Equal(got, tc.pt) {
			t.Fatalf("SM4(%s/%s) round-trip mismatch: got %q want %q", tc.mode, tc.padding, got, tc.pt)
		}
	}
}

// ─── 2. NIST AES-128/256, RFC 8439 ChaCha20, RC4/RC4-dropN ──────────────────

func TestAESNISTVectorsAndModes(t *testing.T) {
	// FIPS 197 Appendix C.1 AES-128 ECB
	key128, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	pt128, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	ct, err := AESEncrypt(pt128, key128, nil, "ecb", "none", nil)
	if err != nil {
		t.Fatalf("AES-128 ECB encrypt failed: %v", err)
	}
	wantECB := "69c4e0d86a7b0430d8cdb78070b4c55a"
	if got := hex.EncodeToString(ct); got != wantECB {
		t.Fatalf("FIPS 197 AES-128 ECB mismatch: got %s want %s", got, wantECB)
	}

	// NIST SP 800-38A F.2.1 AES-128 CBC
	cbcKey, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	cbcIV, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	cbcPT, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
	wantCBC := "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
	gotCBC, err := AESEncrypt(cbcPT, cbcKey, cbcIV, "cbc", "none", nil)
	if err != nil {
		t.Fatalf("AES-128 CBC encrypt failed: %v", err)
	}
	if hex.EncodeToString(gotCBC) != wantCBC {
		t.Fatalf("NIST AES-128 CBC mismatch: got %x want %s", gotCBC, wantCBC)
	}
	decCBC, err := AESDecrypt(gotCBC, cbcKey, cbcIV, "cbc", "none", nil)
	if err != nil || !bytes.Equal(decCBC, cbcPT) {
		t.Fatalf("AES-128 CBC decrypt failed: err=%v", err)
	}

	// NIST SP 800-38A F.2.5 AES-256 CBC
	key256, _ := hex.DecodeString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	wantCBC256 := "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
	gotCBC256, err := AESEncrypt(cbcPT, key256, cbcIV, "cbc", "none", nil)
	if err != nil || hex.EncodeToString(gotCBC256) != wantCBC256 {
		t.Fatalf("NIST AES-256 CBC mismatch: got %x want %s err=%v", gotCBC256, wantCBC256, err)
	}

	// NIST SP 800-38A F.5.1 AES-128 CTR
	ctrIV, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	wantCTR := "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
	gotCTR, err := AESEncrypt(cbcPT, cbcKey, ctrIV, "ctr", "none", nil)
	if err != nil || hex.EncodeToString(gotCTR) != wantCTR {
		t.Fatalf("NIST AES-128 CTR mismatch: got %x want %s err=%v", gotCTR, wantCTR, err)
	}

	// CFB & OFB round-trips
	msg := []byte("Confidential payload for AES-256 CFB/OFB/GCM verification!")
	for _, mode := range []string{"cfb", "ofb"} {
		enc, err := AESEncrypt(msg, key256, cbcIV, mode, "none", nil)
		if err != nil {
			t.Fatalf("AES-%s encrypt failed: %v", mode, err)
		}
		dec, err := AESDecrypt(enc, key256, cbcIV, mode, "none", nil)
		if err != nil || !bytes.Equal(dec, msg) {
			t.Fatalf("AES-%s round-trip failed: err=%v", mode, err)
		}
	}

	// AES-256-GCM with AAD + tampered AAD rejection
	nonce12, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	aad := []byte("header:v1:authenticated")
	gcmCT, err := AESEncrypt(msg, key256, nonce12, "gcm", "none", aad)
	if err != nil {
		t.Fatalf("AES-256-GCM encrypt failed: %v", err)
	}
	gcmPT, err := AESDecrypt(gcmCT, key256, nonce12, "gcm", "none", aad)
	if err != nil || !bytes.Equal(gcmPT, msg) {
		t.Fatalf("AES-256-GCM decrypt failed: err=%v", err)
	}
	if _, err := AESDecrypt(gcmCT, key256, nonce12, "gcm", "none", []byte("wrong-aad")); err == nil {
		t.Fatalf("AES-256-GCM must fail authentication with mismatched AAD")
	}
}

func TestChaCha20RFC8439Vector(t *testing.T) {
	// RFC 8439 Section 2.3.2 block test vector
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	blockNonce, _ := hex.DecodeString("000000090000004a00000000")
	ks, err := ChaCha20XOR(make([]byte, 64), key, blockNonce, 1)
	if err != nil {
		t.Fatalf("ChaCha20XOR block vector failed: %v", err)
	}
	wantBlock := "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
	if got := hex.EncodeToString(ks); got != wantBlock {
		t.Fatalf("RFC 8439 Section 2.3.2 block vector mismatch:\ngot:  %s\nwant: %s", got, wantBlock)
	}

	// RFC 8439 Section 2.4.2 encryption test vector
	nonce, _ := hex.DecodeString("000000000000004a00000000")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	wantCT := "6e2e359a2568f98041ba0728dd0d6981" +
		"e97e7aec1d4360c20a27afccfd9fae0b" +
		"f91b65c5524733ab8f593dabcd62b357" +
		"1639d624e65152ab8f530c359f0861d8" +
		"07ca0dbf500d6a6156a38e088a22b65e" +
		"52bc514d16ccf806818ce91ab7793736" +
		"5af90bbf74a35be6b40b8eedf2785e42" +
		"874d"

	gotCT, err := ChaCha20XOR(pt, key, nonce, 1)
	if err != nil {
		t.Fatalf("ChaCha20XOR encrypt failed: %v", err)
	}
	if got := hex.EncodeToString(gotCT); got != wantCT {
		t.Fatalf("RFC 8439 ChaCha20 mismatch:\ngot:  %s\nwant: %s", got, wantCT)
	}
	gotPT, err := ChaCha20XOR(gotCT, key, nonce, 1)
	if err != nil || !bytes.Equal(gotPT, pt) {
		t.Fatalf("ChaCha20XOR decrypt failed: err=%v", err)
	}
}

func TestRC4AndRC4DropN(t *testing.T) {
	// RFC 6229 40-bit key test vector
	key, _ := hex.DecodeString("0102030405")
	zeros := make([]byte, 16)
	ks, err := RC4XOR(zeros, key, 0)
	if err != nil {
		t.Fatalf("RC4XOR failed: %v", err)
	}
	wantKS := "b2396305f03dc027ccc3524a0a1118a8"
	if got := hex.EncodeToString(ks); got != wantKS {
		t.Fatalf("RFC 6229 RC4 vector mismatch: got %s want %s", got, wantKS)
	}

	// Verify RC4-drop768 matches encrypting after 768 zero bytes.
	pt := []byte("Secret payload protected by RC4-drop768")
	ctDrop, err := RC4XOR(pt, key, 768)
	if err != nil {
		t.Fatalf("RC4XOR drop=768 failed: %v", err)
	}
	padded := append(make([]byte, 768), pt...)
	ctFull, err := RC4XOR(padded, key, 0)
	if err != nil {
		t.Fatalf("RC4XOR drop=0 failed: %v", err)
	}
	if !bytes.Equal(ctDrop, ctFull[768:]) {
		t.Fatalf("RC4-drop768 keystream mismatch")
	}
	dec, err := RC4XOR(ctDrop, key, 768)
	if err != nil || !bytes.Equal(dec, pt) {
		t.Fatalf("RC4-drop768 decrypt mismatch")
	}
}

// ─── 3. Codecs, Zip-Bomb Bounds, Custom Base64, Custom-IV MD5 & SHA-256 ──────

func TestCustomAlphabetBase64AndCodecs(t *testing.T) {
	// Reversed custom 64-char alphabet common in mobile app obfuscation
	customAlpha := "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
	src := []byte("cap-mobile-reverse-engineering-2026!")

	encPad, err := Base64Encode(src, customAlpha, false)
	if err != nil {
		t.Fatalf("custom Base64Encode failed: %v", err)
	}
	stdEnc, _ := Base64Encode(src, "", false)
	if bytes.Equal(encPad, stdEnc) {
		t.Fatalf("custom alphabet Base64 must differ from standard Base64")
	}
	decPad, err := Base64Decode(encPad, customAlpha, false)
	if err != nil || !bytes.Equal(decPad, src) {
		t.Fatalf("custom Base64Decode failed: err=%v got=%q", err, decPad)
	}

	encRaw, err := Base64Encode(src, customAlpha, true)
	if err != nil {
		t.Fatalf("custom raw Base64Encode failed: %v", err)
	}
	if strings.Contains(string(encRaw), "=") {
		t.Fatalf("raw Base64 output must not contain '=' padding: %s", encRaw)
	}
	decRaw, err := Base64Decode(encRaw, customAlpha, true)
	if err != nil || !bytes.Equal(decRaw, src) {
		t.Fatalf("custom raw Base64Decode failed: err=%v got=%q", err, decRaw)
	}

	if _, err := Base64Encode(src, "short", false); err == nil {
		t.Fatalf("expected error for invalid alphabet length")
	}

	// Base32, Hex, URL
	b32, err := Base32Encode(src, "", true)
	if err != nil {
		t.Fatalf("Base32Encode failed: %v", err)
	}
	if dec32, err := Base32Decode(b32, "", true); err != nil || !bytes.Equal(dec32, src) {
		t.Fatalf("Base32Decode failed: err=%v", err)
	}

	hx := HexEncode([]byte{0xde, 0xad, 0xbe, 0xef}, true, ":")
	if string(hx) != "DE:AD:BE:EF" {
		t.Fatalf("HexEncode mismatch: got %q", hx)
	}
	if decHex, err := HexDecode([]byte("0xDE, 0xAD, 0xBE, 0xEF")); err != nil || hex.EncodeToString(decHex) != "deadbeef" {
		t.Fatalf("HexDecode with 0x list failed: err=%v got=%x", err, decHex)
	}
	if _, err := HexDecode([]byte("a0xb")); err == nil {
		t.Fatalf("HexDecode must reject mid-token '0x' in malformed hex 'a0xb'")
	}

	urlEnc := URLEncode([]byte("a=1&b=hello world"), "query")
	if decURL, err := URLDecode(urlEnc, "query"); err != nil || string(decURL) != "a=1&b=hello world" {
		t.Fatalf("URL round-trip failed: err=%v got=%q", err, decURL)
	}
}

func TestCompressionAndZipBombGuard(t *testing.T) {
	msg := bytes.Repeat([]byte("compress-me-repeatedly-"), 200)

	gz, err := GzipCompress(msg, 6)
	if err != nil {
		t.Fatalf("GzipCompress failed: %v", err)
	}
	if dec, err := GzipDecompress(gz); err != nil || !bytes.Equal(dec, msg) {
		t.Fatalf("GzipDecompress failed: err=%v", err)
	}

	zl, err := ZlibCompress(msg, 6)
	if err != nil {
		t.Fatalf("ZlibCompress failed: %v", err)
	}
	if dec, err := ZlibDecompress(zl); err != nil || !bytes.Equal(dec, msg) {
		t.Fatalf("ZlibDecompress failed: err=%v", err)
	}

	df, err := DeflateCompress(msg, 6)
	if err != nil {
		t.Fatalf("DeflateCompress failed: %v", err)
	}
	if dec, err := DeflateDecompress(df); err != nil || !bytes.Equal(dec, msg) {
		t.Fatalf("DeflateDecompress failed: err=%v", err)
	}

	// Zip-bomb guard: 17 MiB of zeros compresses to ~17 KiB, must be rejected (> 16 MiB cap).
	bombRaw := make([]byte, MaxDecompressedBytes+65536)
	bombGzip, err := GzipCompress(bombRaw, 9)
	if err != nil {
		t.Fatalf("GzipCompress bomb setup failed: %v", err)
	}
	if _, err := GzipDecompress(bombGzip); err == nil || !strings.Contains(err.Error(), "exceeds maximum allowed size") {
		t.Fatalf("expected zip-bomb rejection error, got: %v", err)
	}
}

func TestCustomIVMD5AndSHA256AndHMAC(t *testing.T) {
	// Verify pure-Go MD5WithIV & SHA256WithIV match Go stdlib across block-padding boundaries.
	lengths := []int{0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 129, 250}
	for _, n := range lengths {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte((i*31 + 7) & 0xff)
		}

		stdMD5 := md5.Sum(data)
		gotMD5, err := MD5Sum(data, "0123456789abcdeffedcba9876543210")
		if err != nil || !bytes.Equal(gotMD5, stdMD5[:]) {
			t.Fatalf("MD5 standard IV mismatch at len=%d: got %x want %x err=%v", n, gotMD5, stdMD5, err)
		}

		stdSHA := sha256.Sum256(data)
		gotSHA, err := SHA256Sum(data, "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
		if err != nil || !bytes.Equal(gotSHA, stdSHA[:]) {
			t.Fatalf("SHA256 standard IV mismatch at len=%d: got %x want %x err=%v", n, gotSHA, stdSHA, err)
		}
	}

	// Modified mobile-app IVs must diverge from standard digests and remain deterministic.
	sample := []byte("device_id=abc123&ts=1700000000")
	stdM, _ := MD5Sum(sample, "")
	modM, err := MD5Sum(sample, "1032547698badcfeefcdab8967452301")
	if err != nil {
		t.Fatalf("custom IV MD5 failed: %v", err)
	}
	if bytes.Equal(stdM, modM) {
		t.Fatalf("custom IV MD5 must differ from standard MD5")
	}

	stdS, _ := SHA256Sum(sample, "")
	modS, err := SHA256Sum(sample, "112233445566778899aabbccddeeff0000112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatalf("custom IV SHA256 failed: %v", err)
	}
	if bytes.Equal(stdS, modS) {
		t.Fatalf("custom IV SHA256 must differ from standard SHA256")
	}

	// RFC 4231 Test Case 2 HMAC-SHA256 ("Jefe" / "what do ya want for nothing?")
	mac, err := HMACSum("hmac_sha256", []byte("what do ya want for nothing?"), []byte("Jefe"))
	if err != nil {
		t.Fatalf("HMACSum failed: %v", err)
	}
	wantHMAC := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if hex.EncodeToString(mac) != wantHMAC {
		t.Fatalf("RFC 4231 HMAC-SHA256 mismatch: got %x want %s", mac, wantHMAC)
	}

	// Standard CRC32 check value ("123456789" -> 0xcbf43926)
	c32, err := CRC32Sum([]byte("123456789"), "ieee")
	if err != nil || c32 != 0xcbf43926 {
		t.Fatalf("CRC32 IEEE mismatch: got %08x want cbf43926 err=%v", c32, err)
	}
}

func TestXORAndBruteforce(t *testing.T) {
	pt := []byte("Authorization: Bearer secret_mobile_session_token_99182")
	ct, err := XORBytes(pt, []byte{0x42})
	if err != nil {
		t.Fatalf("XORBytes failed: %v", err)
	}
	cands := XORBruteforce(ct, 5)
	if len(cands) != 5 {
		t.Fatalf("expected 5 candidates, got %d", len(cands))
	}
	if cands[0].KeyByte != 0x42 || cands[0].OutputUTF8 != string(pt) {
		t.Fatalf("XORBruteforce top candidate mismatch: got key=0x%02x text=%q", cands[0].KeyByte, cands[0].OutputUTF8)
	}
}

// ─── 4. Multi-Step Pipeline Engine & Payload Auto-Identifier ─────────────────

func TestPipelineMultiStepAndErrorReporting(t *testing.T) {
	ops := ListOperations()
	if len(ops) < 25 {
		t.Fatalf("expected rich operations catalog, got %d ops", len(ops))
	}
	seenOp := map[string]bool{}
	for _, op := range ops {
		if seenOp[op.Name] {
			t.Fatalf("duplicate operation name %q in catalog", op.Name)
		}
		seenOp[op.Name] = true
	}

	customAlpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	aesKey := "00112233445566778899aabbccddeeff"
	aesIV := "ffeeddccbbaa99887766554433221100"
	orig := `{"uid":1042,"action":"transfer","nonce":"xyz"}`

	encRes := RunPipeline(PipelineRequest{
		Input: orig,
		Steps: []PipelineStep{
			{Op: "gzip_compress"},
			{Op: "xor", Params: map[string]string{"key": "deadbeef", "key_encoding": "hex"}, Disabled: true}, // disabled: must be skipped
			{Op: "aes_encrypt", Params: map[string]string{"key": aesKey, "iv": aesIV, "mode": "cbc", "padding": "pkcs7"}},
			{Op: "base64_encode", Params: map[string]string{"alphabet": customAlpha, "raw": "true"}},
			{Op: "url_encode", Params: map[string]string{"mode": "query"}},
		},
	})
	if !encRes.Success || encRes.FailedStep != -1 {
		t.Fatalf("encode pipeline failed: %+v", encRes)
	}
	if len(encRes.Steps) != 5 || !encRes.Steps[1].Disabled {
		t.Fatalf("expected 5 step results with step 1 disabled, got %+v", encRes.Steps)
	}

	decRes := RunPipeline(PipelineRequest{
		Input: encRes.OutputUTF8,
		Steps: []PipelineStep{
			{Op: "url_decode"},
			{Op: "base64_decode", Params: map[string]string{"alphabet": customAlpha, "raw": "true"}},
			{Op: "aes_decrypt", Params: map[string]string{"key": aesKey, "iv": aesIV, "mode": "cbc", "padding": "pkcs7"}},
			{Op: "gzip_decompress"},
		},
	})
	if !decRes.Success || decRes.OutputUTF8 != orig {
		t.Fatalf("decode pipeline mismatch: success=%v err=%q got=%q want=%q", decRes.Success, decRes.Error, decRes.OutputUTF8, orig)
	}

	// Verify exact failing step index reporting.
	failRes := RunPipeline(PipelineRequest{
		Input: "48656c6c6f",
		Steps: []PipelineStep{
			{Op: "hex_decode"},
			{Op: "gzip_decompress"}, // not gzip -> must fail at index 1
			{Op: "base64_encode"},
		},
	})
	if failRes.Success || failRes.FailedStep != 1 || failRes.Steps[1].Error == "" {
		t.Fatalf("expected failure at step 1, got %+v", failRes)
	}
}

func TestPipelineAllOperationBranches(t *testing.T) {
	// Exercise SM4, ChaCha20, RC4, Base32, Zlib, Deflate, XOR bruteforce, hashes, HMAC, CRC32, and Protobuf via RunPipeline.
	res := RunPipeline(PipelineRequest{
		Input: "The quick brown fox jumps over the lazy dog",
		Steps: []PipelineStep{
			{Op: "zlib_compress"},
			{Op: "deflate_compress"},
			{Op: "sm4_encrypt", Params: map[string]string{"key": "0123456789abcdeffedcba9876543210", "iv": "fedcba98765432100123456789abcdef", "mode": "cbc"}},
			{Op: "chacha20_encrypt", Params: map[string]string{"key": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "nonce": "000000000000004a00000000", "counter": "1"}},
			{Op: "rc4_encrypt", Params: map[string]string{"key": "0102030405", "drop": "256"}},
			{Op: "base32_encode"},
			{Op: "hex_encode"},
			{Op: "hex_decode"},
			{Op: "base32_decode"},
			{Op: "rc4_decrypt", Params: map[string]string{"key": "0102030405", "drop": "256"}},
			{Op: "chacha20_decrypt", Params: map[string]string{"key": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "nonce": "000000000000004a00000000", "counter": "1"}},
			{Op: "sm4_decrypt", Params: map[string]string{"key": "0123456789abcdeffedcba9876543210", "iv": "fedcba98765432100123456789abcdef", "mode": "cbc"}},
			{Op: "deflate_decompress"},
			{Op: "zlib_decompress"},
		},
	})
	if !res.Success || res.OutputUTF8 != "The quick brown fox jumps over the lazy dog" {
		t.Fatalf("full round-trip pipeline failed: err=%q out=%q", res.Error, res.OutputUTF8)
	}

	// XOR bruteforce pipeline step (output_mode=best)
	xorRes := RunPipeline(PipelineRequest{
		Input: "Authorization: Bearer token_1234567890",
		Steps: []PipelineStep{
			{Op: "xor", Params: map[string]string{"key": "5a", "key_encoding": "hex"}},
			{Op: "xor_bruteforce", Params: map[string]string{"output_mode": "best"}},
		},
	})
	if !xorRes.Success || xorRes.OutputUTF8 != "Authorization: Bearer token_1234567890" {
		t.Fatalf("xor_bruteforce pipeline failed: err=%q out=%q", xorRes.Error, xorRes.OutputUTF8)
	}

	// Hashes, HMACs, CRC32 via pipeline
	for _, op := range []string{"md5", "sha1", "sha256", "sha512", "crc32"} {
		r := RunPipeline(PipelineRequest{Input: "123456789", Steps: []PipelineStep{{Op: op}}})
		if !r.Success || r.OutputUTF8 == "" {
			t.Fatalf("hash op %s failed: %+v", op, r)
		}
	}
	for _, op := range []string{"hmac_md5", "hmac_sha1", "hmac_sha256", "hmac_sha512"} {
		r := RunPipeline(PipelineRequest{
			Input: "payload",
			Steps: []PipelineStep{{Op: op, Params: map[string]string{"key": "secret"}}},
		})
		if !r.Success || r.OutputUTF8 == "" {
			t.Fatalf("hmac op %s failed: %+v", op, r)
		}
	}

	// Protobuf decode step via pipeline
	pbHex := hex.EncodeToString(buildSampleProtobufWire(t))
	pbRes := RunPipeline(PipelineRequest{
		Input:         pbHex,
		InputEncoding: "hex",
		Steps:         []PipelineStep{{Op: "protobuf_decode"}},
	})
	if !pbRes.Success || !strings.Contains(pbRes.OutputUTF8, `"alice"`) {
		t.Fatalf("protobuf_decode pipeline failed: %+v", pbRes)
	}
}

func TestIdentifyPayloadHeuristics(t *testing.T) {
	// 1. JWT detection with header/payload preview
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user_42","role":"admin"}`))
	jwtStr := hdr + "." + pay + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	idJWT := IdentifyPayload(jwtStr)
	if idJWT.JWT == nil || idJWT.JWT.Algorithm != "HS256" || !strings.Contains(idJWT.JWT.PayloadJSON, "user_42") {
		t.Fatalf("JWT identification failed: %+v", idJWT)
	}

	// 2. Base64-wrapped Gzip -> recommends base64_decode -> gzip_decompress
	gz, _ := GzipCompress([]byte("hidden compressed json payload"), 6)
	b64Gz := base64.StdEncoding.EncodeToString(gz)
	idGz := IdentifyPayload(b64Gz)
	foundGzip := false
	for _, c := range idGz.Candidates {
		if c.Format == "gzip" && c.Confidence >= 0.95 {
			foundGzip = true
		}
	}
	if !foundGzip || len(idGz.Recipes) < 2 {
		t.Fatalf("expected base64+gzip detection and recipes, got %+v", idGz)
	}

	// 3. SHA-256 digest length detection
	shaHex := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("abc")); return s[:] }())
	idSHA := IdentifyPayload(shaHex)
	foundSHA := false
	for _, c := range idSHA.Candidates {
		if c.Format == "sha256_digest" {
			foundSHA = true
		}
	}
	if !foundSHA {
		t.Fatalf("expected sha256_digest candidate, got %+v", idSHA.Candidates)
	}

	// 4. UUID detection
	idUUID := IdentifyPayload("550e8400-e29b-41d4-a716-446655440000")
	if len(idUUID.Candidates) == 0 || idUUID.Candidates[0].Format != "uuid" {
		t.Fatalf("expected uuid candidate, got %+v", idUUID.Candidates)
	}

	// 5. Hex-wrapped Protobuf detection
	pbWire := buildSampleProtobufWire(t)
	idPB := IdentifyPayload(hex.EncodeToString(pbWire))
	foundPB := false
	for _, c := range idPB.Candidates {
		if c.Format == "protobuf" {
			foundPB = true
		}
	}
	if !foundPB {
		t.Fatalf("expected protobuf candidate inside hex payload, got %+v", idPB.Candidates)
	}
}

// ─── 5. Schema-less Protobuf Wire Decode + Tamper + Re-Encode Round-Trip ─────

func buildSampleProtobufWire(t *testing.T) []byte {
	t.Helper()
	// Build inner message: field 1 = string "alice", field 2 = sint64(-12345)
	var inner []byte
	inner = appendProtoVarint(inner, (1<<3)|protoWireBytes)
	inner = appendProtoVarint(inner, 5)
	inner = append(inner, []byte("alice")...)
	inner = appendProtoVarint(inner, (2<<3)|protoWireVarint)
	inner = appendProtoVarint(inner, zigzagEncode64(-12345))

	// Build outer message covering all wire types:
	// field 1: varint 150
	// field 2: string "hi" (short ASCII string must NOT be misclassified as nested message!)
	// field 3: fixed64 (IEEE-754 double 3.141592653589793)
	// field 4: fixed32 (IEEE-754 float 2.5)
	// field 5: embedded message (inner)
	// field 6: raw non-UTF-8 bytes {0xff, 0x00, 0xab, 0xcd}
	var out []byte
	out = appendProtoVarint(out, (1<<3)|protoWireVarint)
	out = appendProtoVarint(out, 150)

	out = appendProtoVarint(out, (2<<3)|protoWireBytes)
	out = appendProtoVarint(out, 2)
	out = append(out, []byte("hi")...)

	out = appendProtoVarint(out, (3<<3)|protoWireFixed64)
	var f64 [8]byte
	binary.LittleEndian.PutUint64(f64[:], math.Float64bits(3.141592653589793))
	out = append(out, f64[:]...)

	out = appendProtoVarint(out, (4<<3)|protoWireFixed32)
	var f32 [4]byte
	binary.LittleEndian.PutUint32(f32[:], math.Float32bits(2.5))
	out = append(out, f32[:]...)

	out = appendProtoVarint(out, (5<<3)|protoWireBytes)
	out = appendProtoVarint(out, uint64(len(inner)))
	out = append(out, inner...)

	out = appendProtoVarint(out, (6<<3)|protoWireBytes)
	out = appendProtoVarint(out, 4)
	out = append(out, 0xff, 0x00, 0xab, 0xcd)

	return out
}

func TestProtobufDecodeTamperAndExactReEncode(t *testing.T) {
	wire := buildSampleProtobufWire(t)

	node, err := DecodeProtobufRaw(wire)
	if err != nil {
		t.Fatalf("DecodeProtobufRaw failed: %v", err)
	}
	if len(node.Fields) != 6 {
		t.Fatalf("expected 6 top-level fields, got %d", len(node.Fields))
	}

	// Verify each wire type & interpretation.
	if node.Fields[0].Kind != "varint" || *node.Fields[0].VarintU64 != 150 {
		t.Fatalf("field 1 mismatch: %+v", node.Fields[0])
	}
	if node.Fields[1].Kind != "string" || node.Fields[1].StringVal != "hi" {
		t.Fatalf("short ASCII string field 2 misclassified: %+v", node.Fields[1])
	}
	if node.Fields[2].DoubleVal == nil || math.Abs(*node.Fields[2].DoubleVal-3.141592653589793) > 1e-12 {
		t.Fatalf("field 3 double mismatch: %+v", node.Fields[2])
	}
	if node.Fields[3].FloatVal == nil || math.Abs(*node.Fields[3].FloatVal-2.5) > 1e-6 {
		t.Fatalf("field 4 float mismatch: %+v", node.Fields[3])
	}
	if node.Fields[4].Kind != "message" || node.Fields[4].Nested == nil || len(node.Fields[4].Nested.Fields) != 2 {
		t.Fatalf("field 5 nested message mismatch: %+v", node.Fields[4])
	}
	if node.Fields[4].Nested.Fields[0].StringVal != "alice" || *node.Fields[4].Nested.Fields[1].VarintS64 != -12345 {
		t.Fatalf("nested field mismatch: %+v", node.Fields[4].Nested.Fields)
	}
	if node.Fields[5].Kind != "bytes" || node.Fields[5].BytesHex != "ff00abcd" {
		t.Fatalf("field 6 raw bytes mismatch: %+v", node.Fields[5])
	}

	// Untouched round-trip MUST match original wire bytes bit-for-bit!
	reEncoded, err := EncodeProtobufRaw(node)
	if err != nil {
		t.Fatalf("EncodeProtobufRaw failed: %v", err)
	}
	if !bytes.Equal(reEncoded, wire) {
		t.Fatalf("exact wire round-trip mismatch:\ngot:  %x\nwant: %x", reEncoded, wire)
	}

	// Tamper nested user name ("alice" -> "admin_vip") and field 1 varint (150 -> 999999) via JSON round-trip!
	rawJSON, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("json.Marshal(ProtoMessageNode) failed: %v", err)
	}
	var edited ProtoMessageNode
	if err := json.Unmarshal(rawJSON, &edited); err != nil {
		t.Fatalf("json.Unmarshal(ProtoMessageNode) failed: %v", err)
	}
	newUID := uint64(999999)
	edited.Fields[0].VarintU64 = &newUID
	edited.Fields[4].Nested.Fields[0].StringVal = "admin_vip"

	tamperedWire, err := EncodeProtobufRaw(&edited)
	if err != nil {
		t.Fatalf("EncodeProtobufRaw(edited) failed: %v", err)
	}
	reDecoded, err := DecodeProtobufRaw(tamperedWire)
	if err != nil {
		t.Fatalf("DecodeProtobufRaw(tampered) failed: %v", err)
	}
	if *reDecoded.Fields[0].VarintU64 != 999999 {
		t.Fatalf("tampered varint not reflected: got %d", *reDecoded.Fields[0].VarintU64)
	}
	if reDecoded.Fields[4].Nested.Fields[0].StringVal != "admin_vip" {
		t.Fatalf("tampered nested string not reflected: got %q", reDecoded.Fields[4].Nested.Fields[0].StringVal)
	}
	if reDecoded.Fields[5].BytesHex != "ff00abcd" {
		t.Fatalf("untouched sibling field corrupted: got %s", reDecoded.Fields[5].BytesHex)
	}

	// Verify max recursion depth guard (20 nested levels) does not crash and marks Truncated.
	deep := []byte{0x08, 0x01} // field 1 = varint 1
	for d := 0; d < 20; d++ {
		var wrap []byte
		wrap = appendProtoVarint(wrap, (1<<3)|protoWireBytes)
		wrap = appendProtoVarint(wrap, uint64(len(deep)))
		wrap = append(wrap, deep...)
		deep = wrap
	}
	deepNode, err := DecodeProtobufRaw(deep)
	if err != nil {
		t.Fatalf("deep protobuf decode failed: %v", err)
	}
	reDeep, err := EncodeProtobufRaw(deepNode)
	if err != nil || !bytes.Equal(reDeep, deep) {
		t.Fatalf("deep protobuf lossless round-trip failed: err=%v", err)
	}
}

// ─── 6. End-to-End White-Box AES-128 Round-9 DFA Master-Key Recovery ─────────

func TestWhiteBoxAES128DFAEndToEnd(t *testing.T) {
	// 1. Verify simulator's AES-128 matches crypto/aes stdlib bit-for-bit + InvertAES128KeySchedule.
	var nistKey, nistPT [16]byte
	_, _ = hex.Decode(nistKey[:], []byte("2b7e151628aed2a6abf7158809cf4f3c"))
	_, _ = hex.Decode(nistPT[:], []byte("3243f6a8885a308d313198a2e0370734"))

	rks := expandAES128Key(nistKey)
	if inv := InvertAES128KeySchedule(rks[10]); inv != nistKey {
		t.Fatalf("InvertAES128KeySchedule failed: got %x want %x", inv, nistKey)
	}
	validSim, _ := SimulateAES128Round9Fault(nistKey, nistPT, 0, 0x01)
	blk, _ := aes.NewCipher(nistKey[:])
	var stdCT [16]byte
	blk.Encrypt(stdCT[:], nistPT[:])
	if validSim != stdCT {
		t.Fatalf("SimulateAES128Round9Fault AES-128 mismatch vs crypto/aes: got %x want %x", validSim, stdCT)
	}

	// 2. Real end-to-end DFA recovery across 10 fresh cryptographically random 128-bit master keys!
	// Each run injects exactly 8 Round-9 faults (2 per ShiftRows column: byte indices 0, 4, 8, 12)
	// plus noisy non-Round-9 / duplicate ciphertexts to verify robust filtering.
	for trial := 0; trial < 10; trial++ {
		var masterKey, pt [16]byte
		if _, err := rand.Read(masterKey[:]); err != nil {
			t.Fatalf("rand.Read key failed: %v", err)
		}
		if _, err := rand.Read(pt[:]); err != nil {
			t.Fatalf("rand.Read pt failed: %v", err)
		}

		var validCT [16]byte
		faultyHexes := make([]string, 0, 10)
		// 2 faults per column (4 columns * 2 = 8 faults total)
		for col := 0; col < 4; col++ {
			for _, mask := range []byte{0x01, 0x5a} {
				vCT, fCT := SimulateAES128Round9Fault(masterKey, pt, col*4+(trial%4), mask)
				validCT = vCT
				faultyHexes = append(faultyHexes, hex.EncodeToString(fCT[:]))
			}
		}
		// Inject a duplicate and a wrong-round (single-byte diff) ciphertext that must be ignored cleanly.
		noisyCT := validCT
		noisyCT[0] ^= 0xff
		faultyHexes = append(faultyHexes, hex.EncodeToString(validCT[:]), hex.EncodeToString(noisyCT[:]))

		res, err := SolveAES128DFA(DFARequest{
			ValidCiphertextHex:   hex.EncodeToString(validCT[:]),
			FaultyCiphertextsHex: faultyHexes,
			PlaintextHex:         hex.EncodeToString(pt[:]),
		})
		if err != nil {
			t.Fatalf("trial %d: SolveAES128DFA error: %v", trial, err)
		}
		if !res.Solved {
			// Very rare (~0.02%) chance 2 faults leave 2 candidates in one column; add a 3rd fault and confirm unique solve.
			for col := 0; col < 4; col++ {
				if !res.Columns[col].Solved {
					_, fCT3 := SimulateAES128Round9Fault(masterKey, pt, col*4, 0xa5)
					faultyHexes = append(faultyHexes, hex.EncodeToString(fCT3[:]))
				}
			}
			res, err = SolveAES128DFA(DFARequest{
				ValidCiphertextHex:   hex.EncodeToString(validCT[:]),
				FaultyCiphertextsHex: faultyHexes,
				PlaintextHex:         hex.EncodeToString(pt[:]),
			})
			if err != nil || !res.Solved {
				t.Fatalf("trial %d: DFA failed to solve even with 3rd fault: err=%v res=%+v", trial, err, res)
			}
		}

		wantMaster := hex.EncodeToString(masterKey[:])
		if res.MasterKeyHex != wantMaster {
			t.Fatalf("trial %d: recovered MasterKey mismatch!\ngot:  %s\nwant: %s", trial, res.MasterKeyHex, wantMaster)
		}
		if !res.VerifiedWithPlaintext {
			t.Fatalf("trial %d: expected VerifiedWithPlaintext=true", trial)
		}
		if res.IgnoredFaults < 2 {
			t.Fatalf("trial %d: expected duplicate+noisy faults to be ignored, got IgnoredFaults=%d", trial, res.IgnoredFaults)
		}
	}

	// 3. Partial faults (only 1 fault in column 0) must report Solved=false with diagnostic candidate count > 1.
	vCT, fCT := SimulateAES128Round9Fault(nistKey, nistPT, 0, 0x01)
	partial, err := SolveAES128DFA(DFARequest{
		ValidCiphertextHex:   hex.EncodeToString(vCT[:]),
		FaultyCiphertextsHex: []string{hex.EncodeToString(fCT[:])},
	})
	if err != nil {
		t.Fatalf("partial DFA returned unexpected error: %v", err)
	}
	if partial.Solved {
		t.Fatalf("1 single fault must not claim Solved=true")
	}
	if partial.Columns[0].FaultCount != 1 || partial.Columns[0].CandidateCount == 0 {
		t.Fatalf("unexpected column 0 partial state: %+v", partial.Columns[0])
	}

	// 4. Concurrency safety under -race.
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var faults []string
			var v [16]byte
			for col := 0; col < 4; col++ {
				v1, f1 := SimulateAES128Round9Fault(nistKey, nistPT, col*4, byte(idx+1))
				_, f2 := SimulateAES128Round9Fault(nistKey, nistPT, col*4, byte(idx+0x41))
				v = v1
				faults = append(faults, hex.EncodeToString(f1[:]), hex.EncodeToString(f2[:]))
			}
			r, err := SolveAES128DFA(DFARequest{
				ValidCiphertextHex:   hex.EncodeToString(v[:]),
				FaultyCiphertextsHex: faults,
			})
			if err != nil || !r.Solved || r.MasterKeyHex != hex.EncodeToString(nistKey[:]) {
				t.Errorf("concurrent DFA goroutine %d failed: err=%v res=%+v", idx, err, r)
			}
		}(g)
	}
	wg.Wait()
}

// ─── 7. Fault-Injection Script Generators + python3 -m py_compile ────────────

func TestGenerateDFAFaultScriptsAndPyCompile(t *testing.T) {
	cfg := DFAScriptConfig{
		BinaryPath:      "/tmp/libwbaes.so",
		APKPath:         "/tmp/app.apk",
		PackageName:     "com.demo.wb",
		Arch:            "arm64",
		TargetClass:     "com/demo/wb/Crypto",
		TargetMethod:    "wbEncrypt",
		MethodSignature: "([B)[B",
		TargetSymbol:    "wb_aes_128",
		TargetAddr:      "0x2200",
		FaultHookAddr:   "0x2680",
		StateBufReg:     "x8",
		PlaintextHex:    "00112233445566778899aabbccddeeff",
		FaultXOR:        0x01,
		FaultsPerByte:   2,
		ClassName:       "DemoWbDfaHarness",
	}

	// Verify Unidbg Java script generation.
	javaScript := GenerateDFAFaultScript("unidbg", cfg)
	if javaScript.Engine != "unidbg" || javaScript.Language != "java" || javaScript.FileName != "DemoWbDfaHarness.java" {
		t.Fatalf("unexpected Unidbg metadata: %+v", javaScript)
	}
	for _, needle := range []string{
		"public class DemoWbDfaHarness extends AbstractJni",
		"Arm64Const.UC_ARM64_REG_X8",
		"[CAP_RE]",
		`\"kind\":\"dfa_pair\"`,
		"0x2680",
	} {
		if !strings.Contains(javaScript.Code, needle) {
			t.Fatalf("Unidbg script missing expected fragment %q", needle)
		}
	}

	// Verify Qiling Python script generation across all supported architectures with python3 -m py_compile!
	pyBin, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 required for py_compile verification: %v", err)
	}

	for _, arch := range []string{"arm64", "arm", "x86_64"} {
		c := cfg
		c.Arch = arch
		c.StateBufReg = "" // exercise default per-arch register selection
		pyScript := GenerateDFAFaultScript("qiling", c)
		if pyScript.Engine != "qiling" || pyScript.Language != "python" {
			t.Fatalf("unexpected Qiling metadata for %s: %+v", arch, pyScript)
		}
		for _, needle := range []string{"[CAP_RE]", `"dfa_pair"`, "FAULT_MASKS", "ql.hook_address"} {
			if !strings.Contains(pyScript.Code, needle) {
				t.Fatalf("Qiling (%s) script missing expected fragment %q", arch, needle)
			}
		}

		tmpPath := filepath.Join(t.TempDir(), "dfa_"+arch+".py")
		if err := os.WriteFile(tmpPath, []byte(pyScript.Code), 0o600); err != nil {
			t.Fatalf("write temp python script: %v", err)
		}
		cmd := exec.Command(pyBin, "-m", "py_compile", tmpPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("python3 -m py_compile failed for %s: %v\noutput:\n%s", arch, err, string(out))
		}
	}

	// Verify crafted inputs with quotes/newlines cannot break generated Python syntax or Java comment framing.
	crafted := cfg
	crafted.BinaryPath = "/tmp/evil\"\nprint('pwned')#.so"
	crafted.TargetSymbol = "sym\"\"\"\nimport os"
	crafted.Arch = "arm64\"\"\"\nimport os"
	craftedPy := GenerateDFAFaultScript("qiling", crafted)
	tmpCrafted := filepath.Join(t.TempDir(), "dfa_crafted.py")
	if err := os.WriteFile(tmpCrafted, []byte(craftedPy.Code), 0o600); err != nil {
		t.Fatalf("write crafted python script: %v", err)
	}
	if out, err := exec.Command(pyBin, "-m", "py_compile", tmpCrafted).CombinedOutput(); err != nil {
		t.Fatalf("python3 -m py_compile failed on crafted input: %v\n%s", err, string(out))
	}
	craftedJava := GenerateDFAFaultScript("unidbg", crafted)
	if strings.Contains(craftedJava.Code, "\nprint('pwned')") {
		t.Fatalf("newline broke out of Java comment in Unidbg script")
	}
}
