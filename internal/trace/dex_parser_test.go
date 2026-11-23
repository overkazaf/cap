package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"path/filepath"
	"slices"
	"testing"
)

// syntheticDexBuilder constructs valid, minimal DEX 035 binaries in memory for
// hermetic unit testing without external tools (javac/d8/dx).
type syntheticDexBuilder struct {
	version    string
	strings    []string
	stringIdx  map[string]uint32
	types      []uint32 // string indices
	typeIdx    map[string]uint32
	protos     []dexTestProto
	protoIdx   map[string]uint32
	methods    []dexTestMethodID
	methodIdx  map[string]uint32
	classDefs  []dexTestClassDef
}

type dexTestProto struct {
	shortyIdx uint32
	retType   uint32
	params    []uint32
}

type dexTestMethodID struct {
	classType uint32
	protoIdx  uint32
	nameIdx   uint32
}

type dexTestMethodDef struct {
	methodIdx   uint32
	accessFlags uint32
	insns       []uint16 // nil => code_off = 0 (e.g. native/abstract)
}

type dexTestClassDef struct {
	classType      uint32
	directMethods  []dexTestMethodDef
	virtualMethods []dexTestMethodDef
}

func newSyntheticDexBuilder() *syntheticDexBuilder {
	return &syntheticDexBuilder{
		version:   "035",
		stringIdx: make(map[string]uint32),
		typeIdx:   make(map[string]uint32),
		protoIdx:  make(map[string]uint32),
		methodIdx: make(map[string]uint32),
	}
}

func (b *syntheticDexBuilder) addString(s string) uint32 {
	if idx, ok := b.stringIdx[s]; ok {
		return idx
	}
	idx := uint32(len(b.strings))
	b.strings = append(b.strings, s)
	b.stringIdx[s] = idx
	return idx
}

func (b *syntheticDexBuilder) addType(desc string) uint32 {
	if idx, ok := b.typeIdx[desc]; ok {
		return idx
	}
	sIdx := b.addString(desc)
	idx := uint32(len(b.types))
	b.types = append(b.types, sIdx)
	b.typeIdx[desc] = idx
	return idx
}

func (b *syntheticDexBuilder) addProto(retDesc string, paramDescs ...string) uint32 {
	key := "("
	for _, p := range paramDescs {
		key += p
	}
	key += ")" + retDesc
	if idx, ok := b.protoIdx[key]; ok {
		return idx
	}
	shorty := shortyChar(retDesc)
	params := make([]uint32, len(paramDescs))
	for i, p := range paramDescs {
		shorty += shortyChar(p)
		params[i] = b.addType(p)
	}
	shortyIdx := b.addString(shorty)
	retIdx := b.addType(retDesc)
	idx := uint32(len(b.protos))
	b.protos = append(b.protos, dexTestProto{
		shortyIdx: shortyIdx,
		retType:   retIdx,
		params:    params,
	})
	b.protoIdx[key] = idx
	return idx
}

func shortyChar(desc string) string {
	if desc == "" {
		return "V"
	}
	switch desc[0] {
	case 'L', '[':
		return "L"
	default:
		return desc[:1]
	}
}

func (b *syntheticDexBuilder) addMethodID(classDesc, name, retDesc string, paramDescs ...string) uint32 {
	protoIdx := b.addProto(retDesc, paramDescs...)
	key := classDesc + "->" + name + ":" + string(rune(protoIdx))
	if idx, ok := b.methodIdx[key]; ok {
		return idx
	}
	cIdx := b.addType(classDesc)
	nIdx := b.addString(name)
	idx := uint32(len(b.methods))
	b.methods = append(b.methods, dexTestMethodID{
		classType: cIdx,
		protoIdx:  protoIdx,
		nameIdx:   nIdx,
	})
	b.methodIdx[key] = idx
	return idx
}

func (b *syntheticDexBuilder) addClass(classDesc string, direct, virtual []dexTestMethodDef) {
	cIdx := b.addType(classDesc)
	b.classDefs = append(b.classDefs, dexTestClassDef{
		classType:      cIdx,
		directMethods:  direct,
		virtualMethods: virtual,
	})
}

func appendULEB128(buf *bytes.Buffer, v uint32) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if v == 0 {
			break
		}
	}
}

func align4(buf *bytes.Buffer) {
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}
}

func (b *syntheticDexBuilder) build() []byte {
	// Layout:
	// [0..112) header
	// string_ids (4 * N)
	// type_ids (4 * N)
	// proto_ids (12 * N)
	// method_ids (8 * N)
	// class_defs (32 * N)
	// data section: string_data_items, type_lists, code_items, class_data_items
	stringIDsOff := uint32(dexHeaderMinSize)
	typeIDsOff := stringIDsOff + uint32(len(b.strings))*4
	protoIDsOff := typeIDsOff + uint32(len(b.types))*4
	methodIDsOff := protoIDsOff + uint32(len(b.protos))*12
	classDefsOff := methodIDsOff + uint32(len(b.methods))*8
	dataStart := classDefsOff + uint32(len(b.classDefs))*32

	var data bytes.Buffer

	// 1. string_data_items
	stringDataOffs := make([]uint32, len(b.strings))
	for i, s := range b.strings {
		stringDataOffs[i] = dataStart + uint32(data.Len())
		appendULEB128(&data, uint32(len([]rune(s))))
		data.WriteString(s)
		data.WriteByte(0)
	}

	// 2. proto parameter type_lists
	protoParamOffs := make([]uint32, len(b.protos))
	for i, p := range b.protos {
		if len(p.params) == 0 {
			continue
		}
		align4(&data)
		protoParamOffs[i] = dataStart + uint32(data.Len())
		_ = binary.Write(&data, binary.LittleEndian, uint32(len(p.params)))
		for _, tIdx := range p.params {
			_ = binary.Write(&data, binary.LittleEndian, uint16(tIdx))
		}
	}

	// 3. code_items + class_data_items
	classDataOffs := make([]uint32, len(b.classDefs))
	for ci, cd := range b.classDefs {
		if len(cd.directMethods) == 0 && len(cd.virtualMethods) == 0 {
			continue
		}
		directCodeOffs := make([]uint32, len(cd.directMethods))
		for i, m := range cd.directMethods {
			if len(m.insns) == 0 {
				continue
			}
			align4(&data)
			directCodeOffs[i] = dataStart + uint32(data.Len())
			writeCodeItem(&data, m.insns)
		}
		virtualCodeOffs := make([]uint32, len(cd.virtualMethods))
		for i, m := range cd.virtualMethods {
			if len(m.insns) == 0 {
				continue
			}
			align4(&data)
			virtualCodeOffs[i] = dataStart + uint32(data.Len())
			writeCodeItem(&data, m.insns)
		}

		classDataOffs[ci] = dataStart + uint32(data.Len())
		appendULEB128(&data, 0) // static_fields_size
		appendULEB128(&data, 0) // instance_fields_size
		appendULEB128(&data, uint32(len(cd.directMethods)))
		appendULEB128(&data, uint32(len(cd.virtualMethods)))

		var prev uint32
		for i, m := range cd.directMethods {
			appendULEB128(&data, m.methodIdx-prev)
			prev = m.methodIdx
			appendULEB128(&data, m.accessFlags)
			appendULEB128(&data, directCodeOffs[i])
		}
		prev = 0
		for i, m := range cd.virtualMethods {
			appendULEB128(&data, m.methodIdx-prev)
			prev = m.methodIdx
			appendULEB128(&data, m.accessFlags)
			appendULEB128(&data, virtualCodeOffs[i])
		}
	}

	totalSize := dataStart + uint32(data.Len())
	out := make([]byte, dataStart, totalSize)

	// Header
	copy(out[0:4], "dex\n")
	copy(out[4:7], b.version)
	out[7] = 0
	binary.LittleEndian.PutUint32(out[0x20:0x24], totalSize)
	binary.LittleEndian.PutUint32(out[0x24:0x28], dexHeaderMinSize)
	binary.LittleEndian.PutUint32(out[0x28:0x2c], dexEndianConstant)
	binary.LittleEndian.PutUint32(out[0x38:0x3c], uint32(len(b.strings)))
	binary.LittleEndian.PutUint32(out[0x3c:0x40], stringIDsOff)
	binary.LittleEndian.PutUint32(out[0x40:0x44], uint32(len(b.types)))
	binary.LittleEndian.PutUint32(out[0x44:0x48], typeIDsOff)
	binary.LittleEndian.PutUint32(out[0x48:0x4c], uint32(len(b.protos)))
	binary.LittleEndian.PutUint32(out[0x4c:0x50], protoIDsOff)
	binary.LittleEndian.PutUint32(out[0x58:0x5c], uint32(len(b.methods)))
	binary.LittleEndian.PutUint32(out[0x5c:0x60], methodIDsOff)
	binary.LittleEndian.PutUint32(out[0x60:0x64], uint32(len(b.classDefs)))
	binary.LittleEndian.PutUint32(out[0x64:0x68], classDefsOff)
	binary.LittleEndian.PutUint32(out[0x68:0x6c], uint32(data.Len()))
	binary.LittleEndian.PutUint32(out[0x6c:0x70], dataStart)

	// string_ids
	for i, off := range stringDataOffs {
		p := int(stringIDsOff) + i*4
		binary.LittleEndian.PutUint32(out[p:p+4], off)
	}
	// type_ids
	for i, sIdx := range b.types {
		p := int(typeIDsOff) + i*4
		binary.LittleEndian.PutUint32(out[p:p+4], sIdx)
	}
	// proto_ids
	for i, pr := range b.protos {
		p := int(protoIDsOff) + i*12
		binary.LittleEndian.PutUint32(out[p:p+4], pr.shortyIdx)
		binary.LittleEndian.PutUint32(out[p+4:p+8], pr.retType)
		binary.LittleEndian.PutUint32(out[p+8:p+12], protoParamOffs[i])
	}
	// method_ids
	for i, m := range b.methods {
		p := int(methodIDsOff) + i*8
		binary.LittleEndian.PutUint16(out[p:p+2], uint16(m.classType))
		binary.LittleEndian.PutUint16(out[p+2:p+4], uint16(m.protoIdx))
		binary.LittleEndian.PutUint32(out[p+4:p+8], m.nameIdx)
	}
	// class_defs
	for i, cd := range b.classDefs {
		p := int(classDefsOff) + i*32
		binary.LittleEndian.PutUint32(out[p:p+4], cd.classType)
		binary.LittleEndian.PutUint32(out[p+24:p+28], classDataOffs[i])
	}

	out = append(out, data.Bytes()...)
	return out
}

func writeCodeItem(buf *bytes.Buffer, insns []uint16) {
	_ = binary.Write(buf, binary.LittleEndian, uint16(4))          // registers_size
	_ = binary.Write(buf, binary.LittleEndian, uint16(1))          // ins_size
	_ = binary.Write(buf, binary.LittleEndian, uint16(2))          // outs_size
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))          // tries_size
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // debug_info_off
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(insns))) // insns_size
	for _, u := range insns {
		_ = binary.Write(buf, binary.LittleEndian, u)
	}
}

// Dalvik instruction encoding helpers
func insnConstString(reg uint8, strIdx uint16) []uint16 {
	return []uint16{uint16(0x1a) | uint16(reg)<<8, strIdx}
}

func insnConstStringJumbo(reg uint8, strIdx uint32) []uint16 {
	return []uint16{
		uint16(0x1b) | uint16(reg)<<8,
		uint16(strIdx & 0xffff),
		uint16(strIdx >> 16),
	}
}

func insnInvoke(op byte, methodIdx uint16) []uint16 {
	return []uint16{uint16(op) | 0x1000, methodIdx, 0x0000}
}

func insnPackedSwitchPayload(targets ...int32) []uint16 {
	u := []uint16{0x0100, uint16(len(targets)), 0x0001, 0x0000}
	for _, t := range targets {
		u = append(u, uint16(uint32(t)&0xffff), uint16(uint32(t)>>16))
	}
	return u
}

func insnSparseSwitchPayload(pairs int) []uint16 {
	u := []uint16{0x0200, uint16(pairs)}
	for i := 0; i < pairs*2; i++ {
		// Embed fake bytes that look like const-string/invoke if mis-parsed!
		u = append(u, 0x001a, 0x006e)
	}
	return u
}

func insnFillArrayDataPayload(elemWidth uint16, elems uint32) []uint16 {
	u := []uint16{
		0x0300,
		elemWidth,
		uint16(elems & 0xffff),
		uint16(elems >> 16),
	}
	units := int((uint64(elems)*uint64(elemWidth) + 1) / 2)
	for i := 0; i < units; i++ {
		u = append(u, 0x016e) // intentionally mimics invoke-virtual byte
	}
	return u
}

func concatInsns(parts ...[]uint16) []uint16 {
	var out []uint16
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestDexParser_ConstStringJumboPayloadsAndMultiDexXRefs(t *testing.T) {
	// DEX 1 (classes.dex):
	// - com.demo.app.ApiClient.fetchUrl:
	//     contains packed-switch, sparse-switch, and fill-array-data payloads BEFORE
	//     const-string("/v1/pay/order"), const-string/jumbo("x-pay-sign"),
	//     invoke-virtual(okhttp3.OkHttpClient.newCall), invoke-static(com.demo.app.Signer.sign)
	// - com.demo.app.Signer.sign:
	//     const-string("x-pay-sign"), invoke-virtual(javax.crypto.Mac.doFinal),
	//     invoke-static(com.demo.app.NativeBridge.nativeSign)
	// - com.demo.app.NativeBridge:
	//     <clinit>: const-string("sec"), invoke-static(java.lang.System.loadLibrary)
	//     nativeSign: ACC_NATIVE (code_off=0)
	// - com.demo.app.MainActivity.onClick:
	//     calls com.demo.app.ApiClient.fetchUrl (same-DEX 1-hop caller!)
	// - com.google.analytics.SdkTracker.track:
	//     const-string("/v1/pay/order") (tests SDK categorization)
	// - com.demo.app.OrderManager.submit:
	//     const-string("/v1/pay/order") (tests business categorization)
	b1 := newSyntheticDexBuilder()

	strURL := b1.addString("https://api.demo.com/v1/pay/order")
	strSignParam := b1.addString("x-pay-sign")
	strLibSec := b1.addString("sec")

	mOkHttpNewCall := b1.addMethodID("Lokhttp3/OkHttpClient;", "newCall", "V", "Ljava/lang/String;")
	mMacDoFinal := b1.addMethodID("Ljavax/crypto/Mac;", "doFinal", "V")
	mLoadLibrary := b1.addMethodID("Ljava/lang/System;", "loadLibrary", "V", "Ljava/lang/String;")
	mStringBuilderAppend := b1.addMethodID("Ljava/lang/StringBuilder;", "append", "Ljava/lang/StringBuilder;", "Ljava/lang/String;")

	mApiFetch := b1.addMethodID("Lcom/demo/app/ApiClient;", "fetchUrl", "Ljava/lang/String;", "Ljava/lang/String;")
	mSignerSign := b1.addMethodID("Lcom/demo/app/Signer;", "sign", "Ljava/lang/String;", "Ljava/lang/String;")
	mNativeClinit := b1.addMethodID("Lcom/demo/app/NativeBridge;", "<clinit>", "V")
	mNativeSign := b1.addMethodID("Lcom/demo/app/NativeBridge;", "nativeSign", "Ljava/lang/String;", "Ljava/lang/String;")
	mMainOnClick := b1.addMethodID("Lcom/demo/app/MainActivity;", "onClick", "V")
	mSdkTrack := b1.addMethodID("Lcom/google/analytics/SdkTracker;", "track", "V")
	mBizSubmit := b1.addMethodID("Lcom/demo/app/OrderManager;", "submit", "V")

	b1.addClass("Lcom/demo/app/ApiClient;", nil, []dexTestMethodDef{
		{
			methodIdx:   mApiFetch,
			accessFlags: 0x0001,
			insns: concatInsns(
				[]uint16{0x0000}, // plain nop
				insnPackedSwitchPayload(10, 20),
				insnSparseSwitchPayload(2),
				insnFillArrayDataPayload(2, 5),
				insnConstString(0, uint16(strURL)),
				insnConstStringJumbo(1, strSignParam),
				insnInvoke(0x6e, uint16(mStringBuilderAppend)), // should be filtered as trivial stdlib
				insnInvoke(0x6e, uint16(mOkHttpNewCall)),       // invoke-virtual
				insnInvoke(0x71, uint16(mSignerSign)),          // invoke-static
				[]uint16{0x000e},                               // return-void
			),
		},
	})

	b1.addClass("Lcom/demo/app/Signer;", []dexTestMethodDef{
		{
			methodIdx:   mSignerSign,
			accessFlags: 0x0009,
			insns: concatInsns(
				insnConstString(0, uint16(strSignParam)),
				insnInvoke(0x6e, uint16(mMacDoFinal)),
				insnInvoke(0x71, uint16(mNativeSign)),
				[]uint16{0x000e},
			),
		},
	}, nil)

	b1.addClass("Lcom/demo/app/NativeBridge;", []dexTestMethodDef{
		{
			methodIdx:   mNativeClinit,
			accessFlags: 0x0008,
			insns: concatInsns(
				insnConstString(0, uint16(strLibSec)),
				insnInvoke(0x71, uint16(mLoadLibrary)),
				[]uint16{0x000e},
			),
		},
		{
			methodIdx:   mNativeSign,
			accessFlags: dexAccNative | 0x0009,
			insns:       nil, // native methods have code_off = 0
		},
	}, nil)

	b1.addClass("Lcom/demo/app/MainActivity;", nil, []dexTestMethodDef{
		{
			methodIdx:   mMainOnClick,
			accessFlags: 0x0001,
			insns: concatInsns(
				insnInvoke(0x74, uint16(mApiFetch)), // invoke-virtual/range
				[]uint16{0x000e},
			),
		},
	})

	b1.addClass("Lcom/google/analytics/SdkTracker;", nil, []dexTestMethodDef{
		{
			methodIdx:   mSdkTrack,
			accessFlags: 0x0001,
			insns: concatInsns(
				insnConstString(0, uint16(strURL)),
				[]uint16{0x000e},
			),
		},
	})

	b1.addClass("Lcom/demo/app/OrderManager;", nil, []dexTestMethodDef{
		{
			methodIdx:   mBizSubmit,
			accessFlags: 0x0001,
			insns: concatInsns(
				insnConstString(0, uint16(strURL)),
				[]uint16{0x000e},
			),
		},
	})

	dex1 := b1.build()

	// DEX 2 (classes2.dex): cross-DEX caller com.demo.ui.CheckoutFragment.pay -> com.demo.app.ApiClient.fetchUrl
	b2 := newSyntheticDexBuilder()
	b2.version = "039"
	mRemoteFetch := b2.addMethodID("Lcom/demo/app/ApiClient;", "fetchUrl", "Ljava/lang/String;", "Ljava/lang/String;")
	mFragPay := b2.addMethodID("Lcom/demo/ui/CheckoutFragment;", "pay", "V")
	b2.addClass("Lcom/demo/ui/CheckoutFragment;", nil, []dexTestMethodDef{
		{
			methodIdx:   mFragPay,
			accessFlags: 0x0001,
			insns: concatInsns(
				insnInvoke(0x6e, uint16(mRemoteFetch)),
				[]uint16{0x000e},
			),
		},
	})
	dex2 := b2.build()

	apkPath := filepath.Join(t.TempDir(), "test.apk")
	writeTestZip(t, apkPath, map[string][]byte{
		"classes.dex":  dex1,
		"classes2.dex": dex2,
		"classes3.dex": []byte("not-a-valid-dex"), // malformed sibling should be skipped gracefully
	})

	res, err := AnalyzeDexXRefsContext(
		context.Background(),
		apkPath,
		[]string{"/v1/pay/order"},
		[]string{"x-pay-sign"},
		50,
	)
	if err != nil {
		t.Fatalf("AnalyzeDexXRefsContext failed: %v", err)
	}

	if res.TotalClasses != 7 {
		t.Fatalf("expected TotalClasses=7, got %d", res.TotalClasses)
	}
	if res.TotalMethods != 8 {
		t.Fatalf("expected TotalMethods=8, got %d", res.TotalMethods)
	}

	byKey := make(map[string]DexMethodRef)
	for _, m := range res.Methods {
		byKey[m.ClassName+"."+m.MethodName] = m
	}

	// 1. Verify ApiClient.fetchUrl (const-string + const-string/jumbo after 3 payload types, callees, cross-DEX callers)
	api, ok := byKey["com.demo.app.ApiClient.fetchUrl"]
	if !ok {
		t.Fatalf("missing com.demo.app.ApiClient.fetchUrl in %+v", res.Methods)
	}
	if api.Descriptor != "(Ljava/lang/String;)Ljava/lang/String;" {
		t.Errorf("unexpected descriptor: %q", api.Descriptor)
	}
	if api.DexFile != "classes.dex" {
		t.Errorf("unexpected dex_file: %q", api.DexFile)
	}
	if api.Category != "network" {
		t.Errorf("expected ApiClient.fetchUrl category=network, got %q", api.Category)
	}
	if !slices.Contains(api.MatchedTerms, "/v1/pay/order") || !slices.Contains(api.MatchedTerms, "x-pay-sign") {
		t.Errorf("expected both const-string and const-string/jumbo matched terms, got %v", api.MatchedTerms)
	}
	if !slices.Contains(api.Callees, "okhttp3.OkHttpClient.newCall") || !slices.Contains(api.Callees, "com.demo.app.Signer.sign") {
		t.Errorf("expected OkHttpClient.newCall & Signer.sign in callees, got %v", api.Callees)
	}
	if slices.Contains(api.Callees, "java.lang.StringBuilder.append") {
		t.Errorf("trivial stdlib callee StringBuilder.append should be filtered out, got %v", api.Callees)
	}
	if !slices.Contains(api.Callers, "com.demo.app.MainActivity.onClick") {
		t.Errorf("expected same-DEX caller MainActivity.onClick, got %v", api.Callers)
	}
	if !slices.Contains(api.Callers, "com.demo.ui.CheckoutFragment.pay") {
		t.Errorf("expected cross-DEX caller CheckoutFragment.pay, got %v", api.Callers)
	}

	// 2. Verify Signer.sign (crypto category, native callee, caller ApiClient.fetchUrl)
	signer, ok := byKey["com.demo.app.Signer.sign"]
	if !ok {
		t.Fatalf("missing com.demo.app.Signer.sign")
	}
	if signer.Category != "crypto" {
		t.Errorf("expected Signer.sign category=crypto, got %q", signer.Category)
	}
	if !slices.Contains(signer.Callees, "com.demo.app.NativeBridge.nativeSign") {
		t.Errorf("expected NativeBridge.nativeSign in Signer.sign callees, got %v", signer.Callees)
	}
	if !slices.Contains(signer.Callers, "com.demo.app.ApiClient.fetchUrl") {
		t.Errorf("expected ApiClient.fetchUrl as caller of Signer.sign, got %v", signer.Callers)
	}

	// 3. Verify System.loadLibrary("sec") -> libsec.so and ACC_NATIVE class summary
	clinit, ok := byKey["com.demo.app.NativeBridge.<clinit>"]
	if !ok {
		t.Fatalf("missing com.demo.app.NativeBridge.<clinit>")
	}
	if clinit.Category != "native" {
		t.Errorf("expected NativeBridge.<clinit> category=native, got %q", clinit.Category)
	}
	if !slices.Contains(clinit.LoadsLibrary, "libsec.so") {
		t.Errorf("expected LoadsLibrary to contain libsec.so, got %v", clinit.LoadsLibrary)
	}
	if !slices.Contains(res.LoadLibraries, "libsec.so") {
		t.Errorf("expected top-level LoadLibraries to contain libsec.so, got %v", res.LoadLibraries)
	}
	if len(res.NativeClasses) != 1 || res.NativeClasses[0].ClassName != "com.demo.app.NativeBridge" {
		t.Fatalf("expected 1 NativeClass com.demo.app.NativeBridge, got %+v", res.NativeClasses)
	}
	if !slices.Contains(res.NativeClasses[0].NativeMethods, "nativeSign") {
		t.Errorf("expected nativeSign in NativeMethods, got %v", res.NativeClasses[0].NativeMethods)
	}

	// 4. Verify SDK & business categories
	if sdk, ok := byKey["com.google.analytics.SdkTracker.track"]; !ok || sdk.Category != "sdk" {
		t.Errorf("expected SdkTracker.track category=sdk, got %+v (ok=%v)", sdk, ok)
	}
	if biz, ok := byKey["com.demo.app.OrderManager.submit"]; !ok || biz.Category != "business" {
		t.Errorf("expected OrderManager.submit category=business, got %+v (ok=%v)", biz, ok)
	}
	if got := categorizeDexSymbol("com.demo.app.MainActivity", "onClick", false, false, false, false); got != "entry" {
		t.Errorf("expected MainActivity category=entry, got %q", got)
	}
}

func TestDexParser_MUTF8AndAnalyzeDexBytes(t *testing.T) {
	b := newSyntheticDexBuilder()
	// Include MUTF-8 encoded NUL (0xC0 0x80) inside a string literal.
	mutf8Str := "api\xc0\x80/v2/secret"
	sIdx := b.addString(mutf8Str)
	mRun := b.addMethodID("Lcom/acme/NetWorker;", "run", "V")
	b.addClass("Lcom/acme/NetWorker;", nil, []dexTestMethodDef{
		{
			methodIdx:   mRun,
			accessFlags: 0x0001,
			insns: concatInsns(
				insnConstString(0, uint16(sIdx)),
				[]uint16{0x000e},
			),
		},
	})

	res, err := AnalyzeDexBytes("classes.dex", b.build(), []string{"/v2/secret"}, nil, 10)
	if err != nil {
		t.Fatalf("AnalyzeDexBytes failed: %v", err)
	}
	if len(res.Methods) != 1 || res.Methods[0].ClassName != "com.acme.NetWorker" {
		t.Fatalf("unexpected methods: %+v", res.Methods)
	}
	if decoded := decodeMUTF8([]byte("a\xc0\x80b")); decoded != "a\x00b" {
		t.Errorf("decodeMUTF8 failed: got %q", decoded)
	}
}

func TestDexParser_MalformedAndTruncatedSafety(t *testing.T) {
	// Build one valid DEX and systematically truncate/corrupt it to prove zero panics.
	b := newSyntheticDexBuilder()
	sIdx := b.addString("https://api.example.com/login")
	mLogin := b.addMethodID("Lcom/example/Auth;", "login", "V")
	b.addClass("Lcom/example/Auth;", nil, []dexTestMethodDef{
		{
			methodIdx:   mLogin,
			accessFlags: 0x0001,
			insns: concatInsns(
				insnFillArrayDataPayload(4, 10),
				insnConstString(0, uint16(sIdx)),
				[]uint16{0x000e},
			),
		},
	})
	validDex := b.build()

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", []byte("dex\n035\x00")},
		{"bad_magic", bytes.Repeat([]byte("A"), 256)},
		{"bad_version", func() []byte {
			d := slices.Clone(validDex)
			d[4] = 'x'
			return d
		}()},
		{"bad_endian", func() []byte {
			d := slices.Clone(validDex)
			binary.LittleEndian.PutUint32(d[0x28:0x2c], 0x78563412)
			return d
		}()},
		{"huge_string_table", func() []byte {
			d := slices.Clone(validDex)
			binary.LittleEndian.PutUint32(d[0x38:0x3c], 0x7fffffff)
			return d
		}()},
		{"corrupt_code_insns_size", func() []byte {
			d := slices.Clone(validDex)
			// Corrupt fill-array-data size to 0xffffffff inside data section
			for i := dexHeaderMinSize; i+8 < len(d); i += 2 {
				if binary.LittleEndian.Uint16(d[i:i+2]) == 0x0300 {
					binary.LittleEndian.PutUint16(d[i+2:i+4], 0xffff)
					binary.LittleEndian.PutUint32(d[i+4:i+8], 0xffffffff)
				}
			}
			return d
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := AnalyzeDexBytes("corrupt.dex", tc.data, []string{"/login"}, nil, 10)
			if err != nil {
				t.Fatalf("expected graceful degradation without error, got: %v", err)
			}
			if res == nil {
				t.Fatal("expected non-nil DexXRefResult")
			}
		})
	}

	// Exhaustive prefix truncation check across every byte boundary.
	for cut := 0; cut < len(validDex); cut += 3 {
		res, err := AnalyzeDexBytes("trunc.dex", validDex[:cut], []string{"/login"}, nil, 10)
		if err != nil || res == nil {
			t.Fatalf("truncation at %d returned err=%v res=%v", cut, err, res)
		}
	}

	// Deterministic random mutation fuzzing (50 mutated buffers with valid header magic).
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 50; i++ {
		mut := slices.Clone(validDex)
		for flips := 0; flips < 12; flips++ {
			idx := 8 + rng.Intn(len(mut)-8)
			mut[idx] = byte(rng.Intn(256))
		}
		if _, err := AnalyzeDexBytes("fuzz.dex", mut, []string{"/login"}, nil, 10); err != nil {
			t.Fatalf("fuzz iteration %d returned error: %v", i, err)
		}
	}
}

func TestDexParser_ContextCancellation(t *testing.T) {
	apkPath := filepath.Join(t.TempDir(), "cancel.apk")
	writeTestZip(t, apkPath, map[string][]byte{
		"classes.dex": newSyntheticDexBuilder().build(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := AnalyzeDexXRefsContext(ctx, apkPath, []string{"/api"}, nil, 10)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
