package cryptolab

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"math/bits"
	"strings"
)

// ─── Block Padding Helpers ───────────────────────────────────────────────────

func padBlock(data []byte, blockSize int, padding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(padding)) {
	case "", "pkcs7", "pkcs5":
		padLen := blockSize - (len(data) % blockSize)
		out := make([]byte, len(data)+padLen)
		copy(out, data)
		for i := len(data); i < len(out); i++ {
			out[i] = byte(padLen)
		}
		return out, nil
	case "zero", "zeros":
		if len(data) == 0 {
			return make([]byte, blockSize), nil
		}
		rem := len(data) % blockSize
		if rem == 0 {
			out := make([]byte, len(data))
			copy(out, data)
			return out, nil
		}
		out := make([]byte, len(data)+(blockSize-rem))
		copy(out, data)
		return out, nil
	case "none", "nopadding":
		if len(data)%blockSize != 0 {
			return nil, fmt.Errorf("plaintext length %d is not a multiple of block size %d with padding=none", len(data), blockSize)
		}
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported padding %q (want pkcs7, zero, or none)", padding)
	}
}

func unpadBlock(data []byte, blockSize int, padding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(padding)) {
	case "", "pkcs7", "pkcs5":
		if len(data) == 0 || len(data)%blockSize != 0 {
			return nil, fmt.Errorf("pkcs7 unpad: invalid length %d", len(data))
		}
		padLen := int(data[len(data)-1])
		if padLen == 0 || padLen > blockSize || padLen > len(data) {
			return nil, fmt.Errorf("pkcs7 unpad: invalid padding byte 0x%02x", padLen)
		}
		for i := len(data) - padLen; i < len(data); i++ {
			if data[i] != byte(padLen) {
				return nil, fmt.Errorf("pkcs7 unpad: malformed padding bytes")
			}
		}
		return data[:len(data)-padLen], nil
	case "zero", "zeros":
		return bytes.TrimRight(data, "\x00"), nil
	case "none", "nopadding":
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported padding %q (want pkcs7, zero, or none)", padding)
	}
}

func ecbEncrypt(block cipher.Block, padded []byte) []byte {
	bs := block.BlockSize()
	out := make([]byte, len(padded))
	for off := 0; off < len(padded); off += bs {
		block.Encrypt(out[off:off+bs], padded[off:off+bs])
	}
	return out
}

func ecbDecrypt(block cipher.Block, ct []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(ct)%bs != 0 {
		return nil, fmt.Errorf("ecb decrypt: ciphertext length %d is not a multiple of block size %d", len(ct), bs)
	}
	out := make([]byte, len(ct))
	for off := 0; off < len(ct); off += bs {
		block.Decrypt(out[off:off+bs], ct[off:off+bs])
	}
	return out, nil
}

// ─── AES-128 / 192 / 256 ─────────────────────────────────────────────────────

// AESEncrypt encrypts plaintext using AES-128/192/256 in ecb, cbc, ctr, cfb, ofb, or gcm mode.
func AESEncrypt(plaintext, key, iv []byte, mode, padding string, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes key: %w", err)
	}
	bs := block.BlockSize()
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ecb":
		padded, err := padBlock(plaintext, bs, padding)
		if err != nil {
			return nil, err
		}
		return ecbEncrypt(block, padded), nil
	case "", "cbc":
		if len(iv) != bs {
			return nil, fmt.Errorf("aes-cbc requires %d-byte IV, got %d", bs, len(iv))
		}
		padded, err := padBlock(plaintext, bs, padding)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return out, nil
	case "ctr":
		if len(iv) != bs {
			return nil, fmt.Errorf("aes-ctr requires %d-byte IV/counter, got %d", bs, len(iv))
		}
		out := make([]byte, len(plaintext))
		cipher.NewCTR(block, iv).XORKeyStream(out, plaintext)
		return out, nil
	case "cfb":
		if len(iv) != bs {
			return nil, fmt.Errorf("aes-cfb requires %d-byte IV, got %d", bs, len(iv))
		}
		out := make([]byte, len(plaintext))
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, plaintext)
		return out, nil
	case "ofb":
		if len(iv) != bs {
			return nil, fmt.Errorf("aes-ofb requires %d-byte IV, got %d", bs, len(iv))
		}
		out := make([]byte, len(plaintext))
		cipher.NewOFB(block, iv).XORKeyStream(out, plaintext)
		return out, nil
	case "gcm":
		if len(iv) == 0 {
			return nil, fmt.Errorf("aes-gcm requires a non-empty nonce (standard 12 bytes)")
		}
		aead, err := newAESGCM(block, len(iv))
		if err != nil {
			return nil, err
		}
		return aead.Seal(nil, iv, plaintext, aad), nil
	default:
		return nil, fmt.Errorf("unsupported aes mode %q (want ecb, cbc, ctr, cfb, ofb, or gcm)", mode)
	}
}

// AESDecrypt decrypts ciphertext using AES-128/192/256 in ecb, cbc, ctr, cfb, ofb, or gcm mode.
func AESDecrypt(ciphertext, key, iv []byte, mode, padding string, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes key: %w", err)
	}
	bs := block.BlockSize()
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ecb":
		raw, err := ecbDecrypt(block, ciphertext)
		if err != nil {
			return nil, err
		}
		return unpadBlock(raw, bs, padding)
	case "", "cbc":
		if len(iv) != bs {
			return nil, fmt.Errorf("aes-cbc requires %d-byte IV, got %d", bs, len(iv))
		}
		if len(ciphertext) == 0 || len(ciphertext)%bs != 0 {
			return nil, fmt.Errorf("aes-cbc ciphertext length %d must be a positive multiple of %d", len(ciphertext), bs)
		}
		raw := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(raw, ciphertext)
		return unpadBlock(raw, bs, padding)
	case "ctr":
		if len(iv) != bs {
			return nil, fmt.Errorf("aes-ctr requires %d-byte IV/counter, got %d", bs, len(iv))
		}
		out := make([]byte, len(ciphertext))
		cipher.NewCTR(block, iv).XORKeyStream(out, ciphertext)
		return out, nil
	case "cfb":
		if len(iv) != bs {
			return nil, fmt.Errorf("aes-cfb requires %d-byte IV, got %d", bs, len(iv))
		}
		out := make([]byte, len(ciphertext))
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, ciphertext)
		return out, nil
	case "ofb":
		if len(iv) != bs {
			return nil, fmt.Errorf("aes-ofb requires %d-byte IV, got %d", bs, len(iv))
		}
		out := make([]byte, len(ciphertext))
		cipher.NewOFB(block, iv).XORKeyStream(out, ciphertext)
		return out, nil
	case "gcm":
		if len(iv) == 0 {
			return nil, fmt.Errorf("aes-gcm requires a non-empty nonce (standard 12 bytes)")
		}
		aead, err := newAESGCM(block, len(iv))
		if err != nil {
			return nil, err
		}
		pt, err := aead.Open(nil, iv, ciphertext, aad)
		if err != nil {
			return nil, fmt.Errorf("aes-gcm decrypt/authenticate failed: %w", err)
		}
		return pt, nil
	default:
		return nil, fmt.Errorf("unsupported aes mode %q (want ecb, cbc, ctr, cfb, ofb, or gcm)", mode)
	}
}

func newAESGCM(block cipher.Block, nonceLen int) (cipher.AEAD, error) {
	if nonceLen == 12 {
		return cipher.NewGCM(block)
	}
	return cipher.NewGCMWithNonceSize(block, nonceLen)
}

// ─── SM4 (GB/T 32907-2016) Pure-Go Implementation ────────────────────────────

// SM4BlockSize is the SM4 block and key size in bytes (128 bits).
const SM4BlockSize = 16

var sm4Sbox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

var sm4FK = [4]uint32{0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc}

var sm4CK = [32]uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
}

type sm4Cipher struct {
	encRK [32]uint32
	decRK [32]uint32
}

func sm4Tau(a uint32) uint32 {
	return uint32(sm4Sbox[a>>24])<<24 |
		uint32(sm4Sbox[(a>>16)&0xff])<<16 |
		uint32(sm4Sbox[(a>>8)&0xff])<<8 |
		uint32(sm4Sbox[a&0xff])
}

func sm4L(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^ bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

func sm4LPrime(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
}

// NewSM4Cipher creates a standard GB/T 32907-2016 SM4 cipher.Block from a 16-byte key.
func NewSM4Cipher(key []byte) (cipher.Block, error) {
	if len(key) != SM4BlockSize {
		return nil, fmt.Errorf("sm4: invalid key size %d (must be 16 bytes)", len(key))
	}
	var c sm4Cipher
	var k [36]uint32
	for i := 0; i < 4; i++ {
		k[i] = binary.BigEndian.Uint32(key[i*4:i*4+4]) ^ sm4FK[i]
	}
	for i := 0; i < 32; i++ {
		t := sm4LPrime(sm4Tau(k[i+1] ^ k[i+2] ^ k[i+3] ^ sm4CK[i]))
		k[i+4] = k[i] ^ t
		c.encRK[i] = k[i+4]
		c.decRK[31-i] = k[i+4]
	}
	return &c, nil
}

func (c *sm4Cipher) BlockSize() int { return SM4BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	sm4CryptBlock(dst, src, &c.encRK)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	sm4CryptBlock(dst, src, &c.decRK)
}

func sm4CryptBlock(dst, src []byte, rk *[32]uint32) {
	x0 := binary.BigEndian.Uint32(src[0:4])
	x1 := binary.BigEndian.Uint32(src[4:8])
	x2 := binary.BigEndian.Uint32(src[8:12])
	x3 := binary.BigEndian.Uint32(src[12:16])

	for i := 0; i < 32; i += 4 {
		x0 ^= sm4L(sm4Tau(x1 ^ x2 ^ x3 ^ rk[i]))
		x1 ^= sm4L(sm4Tau(x2 ^ x3 ^ x0 ^ rk[i+1]))
		x2 ^= sm4L(sm4Tau(x3 ^ x0 ^ x1 ^ rk[i+2]))
		x3 ^= sm4L(sm4Tau(x0 ^ x1 ^ x2 ^ rk[i+3]))
	}

	// Reverse transform R(x32, x33, x34, x35) = (x35, x34, x33, x32).
	binary.BigEndian.PutUint32(dst[0:4], x3)
	binary.BigEndian.PutUint32(dst[4:8], x2)
	binary.BigEndian.PutUint32(dst[8:12], x1)
	binary.BigEndian.PutUint32(dst[12:16], x0)
}

// SM4Encrypt encrypts plaintext using SM4 in ecb, cbc, or ctr mode.
func SM4Encrypt(plaintext, key, iv []byte, mode, padding string) ([]byte, error) {
	block, err := NewSM4Cipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ecb":
		padded, err := padBlock(plaintext, bs, padding)
		if err != nil {
			return nil, err
		}
		return ecbEncrypt(block, padded), nil
	case "", "cbc":
		if len(iv) != bs {
			return nil, fmt.Errorf("sm4-cbc requires %d-byte IV, got %d", bs, len(iv))
		}
		padded, err := padBlock(plaintext, bs, padding)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return out, nil
	case "ctr":
		if len(iv) != bs {
			return nil, fmt.Errorf("sm4-ctr requires %d-byte IV/counter, got %d", bs, len(iv))
		}
		out := make([]byte, len(plaintext))
		cipher.NewCTR(block, iv).XORKeyStream(out, plaintext)
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported sm4 mode %q (want ecb, cbc, or ctr)", mode)
	}
}

// SM4Decrypt decrypts ciphertext using SM4 in ecb, cbc, or ctr mode.
func SM4Decrypt(ciphertext, key, iv []byte, mode, padding string) ([]byte, error) {
	block, err := NewSM4Cipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ecb":
		raw, err := ecbDecrypt(block, ciphertext)
		if err != nil {
			return nil, err
		}
		return unpadBlock(raw, bs, padding)
	case "", "cbc":
		if len(iv) != bs {
			return nil, fmt.Errorf("sm4-cbc requires %d-byte IV, got %d", bs, len(iv))
		}
		if len(ciphertext) == 0 || len(ciphertext)%bs != 0 {
			return nil, fmt.Errorf("sm4-cbc ciphertext length %d must be a positive multiple of %d", len(ciphertext), bs)
		}
		raw := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(raw, ciphertext)
		return unpadBlock(raw, bs, padding)
	case "ctr":
		if len(iv) != bs {
			return nil, fmt.Errorf("sm4-ctr requires %d-byte IV/counter, got %d", bs, len(iv))
		}
		out := make([]byte, len(ciphertext))
		cipher.NewCTR(block, iv).XORKeyStream(out, ciphertext)
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported sm4 mode %q (want ecb, cbc, or ctr)", mode)
	}
}

// ─── ChaCha20 (Pure-Go RFC 8439) ─────────────────────────────────────────────

func chachaQuarterRound(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 16)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 12)
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 8)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 7)
}

func chacha20Block(key []byte, counter uint32, nonce []byte, out *[64]byte) {
	var init [16]uint32
	init[0] = 0x61707865 // "expa"
	init[1] = 0x3320646e // "nd 3"
	init[2] = 0x79622d32 // "2-by"
	init[3] = 0x6b206574 // "te k"
	for i := 0; i < 8; i++ {
		init[4+i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}
	init[12] = counter
	init[13] = binary.LittleEndian.Uint32(nonce[0:4])
	init[14] = binary.LittleEndian.Uint32(nonce[4:8])
	init[15] = binary.LittleEndian.Uint32(nonce[8:12])

	work := init
	for i := 0; i < 10; i++ {
		// Column rounds
		chachaQuarterRound(&work, 0, 4, 8, 12)
		chachaQuarterRound(&work, 1, 5, 9, 13)
		chachaQuarterRound(&work, 2, 6, 10, 14)
		chachaQuarterRound(&work, 3, 7, 11, 15)
		// Diagonal rounds
		chachaQuarterRound(&work, 0, 5, 10, 15)
		chachaQuarterRound(&work, 1, 6, 11, 12)
		chachaQuarterRound(&work, 2, 7, 8, 13)
		chachaQuarterRound(&work, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:i*4+4], work[i]+init[i])
	}
}

// ChaCha20XOR encrypts or decrypts data using RFC 8439 ChaCha20 (32-byte key,
// 12-byte nonce, 32-bit initial block counter).
func ChaCha20XOR(data, key, nonce []byte, counter uint32) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("chacha20: key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("chacha20: nonce must be 12 bytes (RFC 8439), got %d", len(nonce))
	}
	if len(data) > 0 {
		blocks := (uint64(len(data)) + 63) / 64
		if uint64(counter)+blocks > (uint64(1) << 32) {
			return nil, fmt.Errorf("chacha20: 32-bit block counter overflow (counter=%d, blocks=%d)", counter, blocks)
		}
	}
	out := make([]byte, len(data))
	var block [64]byte
	ctr := counter
	for off := 0; off < len(data); off += 64 {
		chacha20Block(key, ctr, nonce, &block)
		n := len(data) - off
		if n > 64 {
			n = 64
		}
		for i := 0; i < n; i++ {
			out[off+i] = data[off+i] ^ block[i]
		}
		ctr++
	}
	return out, nil
}

// ─── RC4 & RC4-dropN ─────────────────────────────────────────────────────────

const maxRC4Drop = 16 << 20

// RC4XOR encrypts or decrypts data with RC4, optionally dropping the first
// drop keystream bytes (RC4-dropN).
func RC4XOR(data, key []byte, drop int) ([]byte, error) {
	if len(key) < 1 || len(key) > 256 {
		return nil, fmt.Errorf("rc4: key length %d out of range [1, 256]", len(key))
	}
	if drop < 0 || drop > maxRC4Drop {
		return nil, fmt.Errorf("rc4: drop count %d out of range [0, %d]", drop, maxRC4Drop)
	}
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("rc4: %w", err)
	}
	if drop > 0 {
		var scratch [4096]byte
		rem := drop
		for rem > 0 {
			chunk := rem
			if chunk > len(scratch) {
				chunk = len(scratch)
			}
			c.XORKeyStream(scratch[:chunk], scratch[:chunk])
			rem -= chunk
		}
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}
