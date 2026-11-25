package repro

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	// Matches inline callback format:
	//   UnsupportedOperationException: callObjectMethodV: android/content/Context->getPackageName()Ljava/lang/String;
	//   UnsupportedOperationException: callStaticObjectMethodV android/provider/Settings$Secure->getString(...)
	inlineCallbackRe = regexp.MustCompile(`UnsupportedOperationException:\s*(callObjectMethodV|callStaticObjectMethodV|getObjectField|getStaticObjectField|getIntField|callIntMethodV|callBooleanMethodV|newObjectV|resolveClass)\s*[:=\s]+\s*([^\s,"']+)`)

	// Matches generic Unidbg UnsupportedOperationException: <signature>
	genericUoeRe = regexp.MustCompile(`UnsupportedOperationException:\s*([^\s,"']+(?:->[^\s,"']+)?)`)

	// Matches AbstractJni stack trace frame:
	//   at com.github.unidbg.linux.android.dvm.AbstractJni.callObjectMethodV(AbstractJni.java:258)
	//   at com.github.unidbg.linux.android.dvm.BaseVM.resolveClass(BaseVM.java:180)
	stackCallbackRe = regexp.MustCompile(`(?:AbstractJni|BaseVM|DvmObject|DalvikVM)\.(callObjectMethodV|callStaticObjectMethodV|getObjectField|getStaticObjectField|getIntField|callIntMethodV|callBooleanMethodV|newObjectV|resolveClass)\s*\(`)

	// Matches explicit resolveClass warnings/exceptions:
	//   resolveClass: com/example/Foo  or  ClassNotFoundException: com/example/Foo
	resolveClassLineRe = regexp.MustCompile(`(?i)(?:resolveClass|ClassNotFoundException)\s*[:=\s]+\s*([A-Za-z0-9_$/\.]+)`)

	// Matches missing file paths opened during emulation (/proc/..., /data/..., /system/..., /sys/..., /dev/..., /vendor/...).
	missingFilePathRe = regexp.MustCompile(`(?i)(?:FileNotFoundException|openat?|pathname\s*=|resolve(?:File)?[^\n]*?failed|No such file[^\n]*?|cannot open|failed to open|open\s*\()[^\n"'/]*(?:["'])?((?:/proc|/data|/system|/sys|/dev|/vendor|/sdcard|/storage|/etc)[A-Za-z0-9_./\-:@$~=+]+)`)

	// Matches __system_property_get / property_get function-style log lines first (so logger prefixes like
	// "(SystemPropertyHook.java:42)" never hijack the match).
	sysPropFuncRe = regexp.MustCompile(`(?i)(?:__system_property_get|system_property_get|property_get)[\s:\-=(,]*(?:(?:key|name|prop|property)\s*[:=]\s*)?["']?([a-z][a-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+)["']?`)

	// Matches explicit missing/unsupported system property messages.
	sysPropMsgRe = regexp.MustCompile(`(?i)(?:missing\s+sys(?:tem)?\s*prop(?:erty)?|unsupported\s+system\s+property)[\s:\-=(,]*(?:(?:key|name|prop|property)\s*[:=]\s*)?["']?([a-z][a-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+)["']?`)

	// Matches key=value or well-known Android property prefixes on SystemPropertyHook lines after stripping logger metadata.
	sysPropHookKeyRe = regexp.MustCompile(`(?i)(?:(?:key|name|prop|property)\s*[:=]\s*["']?([a-z][a-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+)["']?|["']?((?:ro|persist|sys|dalvik|debug|gsm|net|init|service|vendor|hw|ril|crypto|security|pm|media)\.[A-Za-z0-9_.-]+)["']?)`)

	// Strips Log4j/SLF4J logger brackets & Java source locations like "[com.foo.SystemPropertyHook] (SystemPropertyHook.java:42)".
	logMetaStripRe = regexp.MustCompile(`\[[^\]]*\]|\([A-Za-z0-9_$]+\.(?:java|kt):\d+\)`)

	// Matches missing .so library errors.
	missingLibRe = regexp.MustCompile(`(?i)(?:library\s+not\s+found|cannot\s+load\s+library|resolveLibrary[^\n]*?failed|dlopen\s+failed[^\n]*?|need(?:ed)?\s+library|missing\s+library|unable\s+to\s+find\s+library)[^\n]*?(lib[A-Za-z0-9_.+\-]+\.so(?:\.[0-9]+)*)`)
)

// AnalyzeUnidbgLog parses raw Unidbg execution logs, deduplicates missing JNI
// callbacks, classes, filesystem paths, Android system properties, and native
// libraries, and synthesizes ready-to-compile Java stub snippets.
func AnalyzeUnidbgLog(rawLog string) *UnidbgStubDiagnosis {
	diag := &UnidbgStubDiagnosis{
		MissingJNI:       []MissingJNIItem{},
		MissingFiles:     []MissingFileItem{},
		MissingSysProps:  []MissingSysPropItem{},
		MissingLibraries: []MissingLibraryItem{},
		AnalyzedAt:       nowRFC3339(),
	}

	if strings.TrimSpace(rawLog) == "" {
		diag.Summary = "No Unidbg log lines provided."
		return diag
	}

	lines := strings.Split(strings.ReplaceAll(rawLog, "\r\n", "\n"), "\n")

	type jniKey struct {
		callback string
		sig      string
	}
	jniCounts := make(map[jniKey]int)
	jniOrder := make([]jniKey, 0)
	addJNI := func(cb, sig string) {
		sig = strings.TrimSpace(strings.TrimRight(sig, ",\"'"))
		if cb == CallbackResolveClass {
			sig = strings.TrimRight(sig, ";")
		}
		if sig == "" {
			return
		}
		k := jniKey{callback: cb, sig: sig}
		if jniCounts[k] == 0 {
			jniOrder = append(jniOrder, k)
		}
		jniCounts[k]++
		diag.TotalErrors++
	}

	classSet := make(map[string]bool)
	var missingClasses []string
	addClass := func(cls string) {
		cls = strings.TrimSpace(strings.Trim(cls, "\"';,"))
		cls = strings.ReplaceAll(cls, ".", "/")
		if cls == "" || classSet[cls] {
			return
		}
		classSet[cls] = true
		missingClasses = append(missingClasses, cls)
	}

	fileCounts := make(map[string]int)
	var fileOrder []string
	addFile := func(p string) {
		p = strings.TrimSpace(strings.TrimRight(p, ",;\"')"))
		if p == "" {
			return
		}
		if fileCounts[p] == 0 {
			fileOrder = append(fileOrder, p)
		}
		fileCounts[p]++
		diag.TotalErrors++
	}

	propCounts := make(map[string]int)
	var propOrder []string
	addProp := func(k string) {
		k = strings.TrimSpace(strings.Trim(k, "\"',;)"))
		if k == "" || !strings.Contains(k, ".") {
			return
		}
		if propCounts[k] == 0 {
			propOrder = append(propOrder, k)
		}
		propCounts[k]++
		diag.TotalErrors++
	}

	libCounts := make(map[string]int)
	var libOrder []string
	addLib := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if libCounts[name] == 0 {
			libOrder = append(libOrder, name)
		}
		libCounts[name]++
		diag.TotalErrors++
	}

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// 1. Inline callback UnsupportedOperationException
		if m := inlineCallbackRe.FindStringSubmatch(line); len(m) == 3 {
			cb := m[1]
			sig := m[2]
			if cb == CallbackResolveClass {
				addClass(sig)
				addJNI(cb, sig)
			} else {
				addJNI(cb, sig)
			}
			continue
		}

		// 2. Generic UnsupportedOperationException with optional stack trace lookahead
		if m := genericUoeRe.FindStringSubmatch(line); len(m) == 2 {
			sig := strings.TrimSpace(m[1])
			cb := ""
			// Look ahead up to 6 lines for an AbstractJni / BaseVM stack frame.
			for j := i + 1; j < len(lines) && j <= i+6; j++ {
				if sm := stackCallbackRe.FindStringSubmatch(lines[j]); len(sm) == 2 {
					cb = sm[1]
					break
				}
				if strings.Contains(lines[j], "UnsupportedOperationException:") {
					break
				}
			}
			if cb == "" {
				cb = inferCallbackFromSignature(sig)
			}
			if cb == CallbackResolveClass {
				addClass(sig)
			}
			addJNI(cb, sig)
			continue
		}

		// 3. Explicit resolveClass / ClassNotFoundException lines (outside UOE)
		if !strings.Contains(line, "AbstractJni.") && !strings.Contains(line, "BaseVM.") {
			if m := resolveClassLineRe.FindStringSubmatch(line); len(m) == 2 {
				cls := m[1]
				if strings.Contains(cls, "/") || strings.Contains(cls, ".") {
					addClass(cls)
					addJNI(CallbackResolveClass, strings.ReplaceAll(cls, ".", "/"))
				}
			}
		}

		// 4. Missing file paths for IOResolver
		if m := missingFilePathRe.FindStringSubmatch(line); len(m) == 2 {
			addFile(m[1])
		}

		// 5. Missing Android system properties
		if key := extractSysPropFromLine(line); key != "" {
			addProp(key)
		}

		// 6. Missing .so libraries
		if m := missingLibRe.FindStringSubmatch(line); len(m) == 2 {
			addLib(m[1])
		}
	}

	sort.Strings(missingClasses)
	diag.MissingClasses = missingClasses

	// Build MissingJNI items with smart realistic defaults.
	for _, k := range jniOrder {
		cls, member, desc := splitJNISignature(k.sig)
		code, note, smart := synthesizeJNIStubBody(k.callback, k.sig, cls, member, desc)
		diag.MissingJNI = append(diag.MissingJNI, MissingJNIItem{
			Callback:      k.callback,
			Signature:     k.sig,
			ClassName:     cls,
			MemberName:    member,
			Descriptor:    desc,
			Count:         jniCounts[k],
			SmartMatch:    smart,
			SuggestedCode: code,
			Note:          note,
		})
	}

	// Build MissingFiles items.
	for _, p := range fileOrder {
		content, note := suggestFileContent(p)
		diag.MissingFiles = append(diag.MissingFiles, MissingFileItem{
			Path:             p,
			Count:            fileCounts[p],
			SuggestedContent: content,
			Note:             note,
		})
	}

	// Build MissingSysProps items.
	for _, key := range propOrder {
		val, note := suggestSysPropValue(key)
		diag.MissingSysProps = append(diag.MissingSysProps, MissingSysPropItem{
			Key:            key,
			Count:          propCounts[key],
			SuggestedValue: val,
			Note:           note,
		})
	}

	// Build MissingLibraries items.
	for _, lib := range libOrder {
		diag.MissingLibraries = append(diag.MissingLibraries, MissingLibraryItem{
			Name:  lib,
			Count: libCounts[lib],
			Note:  fmt.Sprintf("Place %s in your Unidbg rootfs or load it via vm.loadLibrary(new File(\"%s\"), true) before the target module.", lib, lib),
		})
	}

	diag.AbstractJniSnippet = renderAbstractJniSnippet(diag.MissingJNI)
	diag.IOResolverSnippet = renderIOResolverSnippet(diag.MissingFiles)
	diag.SysPropHookSnippet = renderSysPropHookSnippet(diag.MissingSysProps)
	diag.CombinedJavaSnippet = renderCombinedStubSnippet(diag)

	diag.Summary = fmt.Sprintf(
		"Detected %d log issue(s): %d unique JNI callback(s), %d missing file(s), %d system property key(s), %d missing library(ies).",
		diag.TotalErrors,
		len(diag.MissingJNI),
		len(diag.MissingFiles),
		len(diag.MissingSysProps),
		len(diag.MissingLibraries),
	)
	return diag
}

func extractSysPropFromLine(line string) string {
	isValidPropKey := func(k string) bool {
		k = strings.TrimSpace(strings.Trim(k, "\"',;)"))
		if k == "" || !strings.Contains(k, ".") {
			return false
		}
		low := strings.ToLower(k)
		for _, bad := range []string{".java", ".kt", ".so", ".class", ".dex", ".xml", ".apk"} {
			if strings.HasSuffix(low, bad) {
				return false
			}
		}
		return true
	}

	if m := sysPropFuncRe.FindStringSubmatch(line); len(m) == 2 && isValidPropKey(m[1]) {
		return m[1]
	}
	if m := sysPropMsgRe.FindStringSubmatch(line); len(m) == 2 && isValidPropKey(m[1]) {
		return m[1]
	}
	if strings.Contains(strings.ToLower(line), "systempropertyhook") {
		cleaned := logMetaStripRe.ReplaceAllString(line, " ")
		// Remove bare class name token so it cannot be mistaken for a property key.
		cleaned = strings.ReplaceAll(cleaned, "SystemPropertyHook", " ")
		if m := sysPropHookKeyRe.FindStringSubmatch(cleaned); len(m) >= 3 {
			cand := firstNonEmptyStr(m[1], m[2])
			if isValidPropKey(cand) {
				return cand
			}
		}
	}
	return ""
}

func inferCallbackFromSignature(sig string) string {
	if !strings.Contains(sig, "->") {
		return CallbackResolveClass
	}
	parts := strings.SplitN(sig, "->", 2)
	cls, rest := parts[0], parts[1]
	if strings.HasPrefix(rest, "<init>(") {
		return CallbackNewObjectV
	}
	// Field format: Class->FIELD:Ltype; or Class->FIELD:I
	if !strings.Contains(rest, "(") && strings.Contains(rest, ":") {
		if strings.HasSuffix(rest, ":I") {
			return CallbackGetIntField
		}
		if strings.HasPrefix(cls, "android/os/Build") {
			return CallbackGetStaticObjectField
		}
		return CallbackGetObjectField
	}
	// Method format: inspect return descriptor after ')'
	if idx := strings.LastIndexByte(rest, ')'); idx >= 0 && idx+1 < len(rest) {
		ret := rest[idx+1:]
		switch ret {
		case "I":
			return CallbackCallIntMethodV
		case "Z":
			return CallbackCallBooleanMethodV
		}
	}
	if strings.Contains(cls, "Settings$Secure") || strings.Contains(cls, "SystemProperties") || cls == "java/lang/System" {
		return CallbackCallStaticObjectMethodV
	}
	if cls == "android/app/ActivityThread" && (strings.HasPrefix(rest, "currentActivityThread(") || strings.HasPrefix(rest, "currentApplication(") || strings.HasPrefix(rest, "currentPackageName(")) {
		return CallbackCallStaticObjectMethodV
	}
	return CallbackCallObjectMethodV
}

func splitJNISignature(sig string) (className, memberName, descriptor string) {
	if !strings.Contains(sig, "->") {
		return strings.ReplaceAll(sig, ".", "/"), "", ""
	}
	parts := strings.SplitN(sig, "->", 2)
	className = strings.ReplaceAll(parts[0], ".", "/")
	rest := parts[1]
	if idx := strings.IndexByte(rest, '('); idx >= 0 {
		memberName = rest[:idx]
		descriptor = rest[idx:]
		return
	}
	if idx := strings.IndexByte(rest, ':'); idx >= 0 {
		memberName = rest[:idx]
		descriptor = rest[idx+1:]
		return
	}
	memberName = rest
	return
}

func synthesizeJNIStubBody(callback, sig, cls, member, desc string) (code, note string, smart bool) {
	isIntCB := callback == CallbackCallIntMethodV || callback == CallbackGetIntField
	isBoolCB := callback == CallbackCallBooleanMethodV
	isObjCB := callback == CallbackCallObjectMethodV || callback == CallbackCallStaticObjectMethodV ||
		callback == CallbackGetObjectField || callback == CallbackGetStaticObjectField || callback == CallbackNewObjectV

	// Smart defaults matched by exact signature, strictly respecting the Java return type of callback.
	if isObjCB {
		switch sig {
		case "android/content/Context->getPackageName()Ljava/lang/String;":
			return `return new StringObject(vm, packageName);`, "Returns configured target package name.", true
		case "android/content/Context->getPackageManager()Landroid/content/pm/PackageManager;":
			return `return vm.resolveClass("android/content/pm/PackageManager").newObject(null);`, "Provides stub PackageManager instance.", true
		case "android/content/Context->getContentResolver()Landroid/content/ContentResolver;":
			return `return vm.resolveClass("android/content/ContentResolver").newObject(null);`, "Provides stub ContentResolver instance.", true
		case "android/content/Context->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
			return `return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(null);`, "Provides ApplicationInfo instance (pair with sourceDir/dataDir field stubs).", true
		case "android/content/Context->getFilesDir()Ljava/io/File;":
			return `return vm.resolveClass("java/io/File").newObject("/data/user/0/" + packageName + "/files");`, "Maps app internal files directory.", true
		case "android/content/Context->getCacheDir()Ljava/io/File;":
			return `return vm.resolveClass("java/io/File").newObject("/data/user/0/" + packageName + "/cache");`, "Maps app internal cache directory.", true
		case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;":
			return `String svc = vaList.getObjectArg(0).getValue().toString();
            if ("phone".equals(svc)) {
                return vm.resolveClass("android/telephony/TelephonyManager").newObject(null);
            }
            if ("wifi".equals(svc)) {
                return vm.resolveClass("android/net/wifi/WifiManager").newObject(null);
            }
            return vm.resolveClass("java/lang/Object").newObject(svc);`, "Dispatches common Android system services (phone, wifi).", true
		case "android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;":
			return `String pkg = vaList.getObjectArg(0).getValue().toString();
            int flags = vaList.getIntArg(1);
            return vm.resolveClass("android/content/pm/PackageInfo").newObject(pkg + ":" + flags);`, "Returns PackageInfo wrapper; wire signatures/versionCode fields as needed.", true
		case "android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;":
			return `return new ArrayObject(vm.resolveClass("android/content/pm/Signature").newObject(SIGNING_CERT_HEX));`, "Returns single-element Signature[] populated with signing cert hex.", true
		case "android/content/pm/Signature->toByteArray()[B":
			return `return new ByteArray(vm, hexToBytes(SIGNING_CERT_HEX));`, "Returns DER-encoded APK signing certificate bytes.", true
		case "android/content/pm/Signature->toCharsString()Ljava/lang/String;":
			return `return new StringObject(vm, SIGNING_CERT_HEX);`, "Returns hex string of APK signing certificate.", true
		case "android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;":
			return `String key = vaList.getObjectArg(1).getValue().toString();
            if ("android_id".equals(key)) {
                return new StringObject(vm, ANDROID_ID);
            }
            return new StringObject(vm, "");`, "Returns realistic 64-bit hex android_id for Settings.Secure.ANDROID_ID.", true
		case "android/os/Build->MODEL:Ljava/lang/String;":
			return `return new StringObject(vm, "Pixel 7");`, "Device Build.MODEL.", true
		case "android/os/Build->BRAND:Ljava/lang/String;":
			return `return new StringObject(vm, "google");`, "Device Build.BRAND.", true
		case "android/os/Build->MANUFACTURER:Ljava/lang/String;":
			return `return new StringObject(vm, "Google");`, "Device Build.MANUFACTURER.", true
		case "android/os/Build->FINGERPRINT:Ljava/lang/String;":
			return `return new StringObject(vm, "google/panther/panther:13/TQ3A.230901.001/10750268:user/release-keys");`, "Device Build.FINGERPRINT.", true
		case "android/os/Build->DEVICE:Ljava/lang/String;":
			return `return new StringObject(vm, "panther");`, "Device Build.DEVICE.", true
		case "android/os/Build->PRODUCT:Ljava/lang/String;":
			return `return new StringObject(vm, "panther");`, "Device Build.PRODUCT.", true
		case "android/os/Build->HARDWARE:Ljava/lang/String;":
			return `return new StringObject(vm, "panther");`, "Device Build.HARDWARE.", true
		case "android/os/Build->BOARD:Ljava/lang/String;":
			return `return new StringObject(vm, "panther");`, "Device Build.BOARD.", true
		case "android/os/Build->TAGS:Ljava/lang/String;":
			return `return new StringObject(vm, "release-keys");`, "Device Build.TAGS.", true
		case "android/os/Build->TYPE:Ljava/lang/String;":
			return `return new StringObject(vm, "user");`, "Device Build.TYPE.", true
		case "android/os/Build->ID:Ljava/lang/String;":
			return `return new StringObject(vm, "TQ3A.230901.001");`, "Device Build.ID.", true
		case "android/os/Build->SERIAL:Ljava/lang/String;":
			return `return new StringObject(vm, "unknown");`, "Device Build.SERIAL.", true
		case "android/os/Build$VERSION->RELEASE:Ljava/lang/String;":
			return `return new StringObject(vm, "13");`, "Android OS release version.", true
		case "android/os/Build$VERSION->CODENAME:Ljava/lang/String;":
			return `return new StringObject(vm, "REL");`, "Android OS codename.", true
		case "android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;":
			return `return new StringObject(vm, "/data/app/~~cap==/" + packageName + "/base.apk");`, "APK base path on device.", true
		case "android/content/pm/ApplicationInfo->dataDir:Ljava/lang/String;":
			return `return new StringObject(vm, "/data/user/0/" + packageName);`, "App private data directory.", true
		case "android/content/pm/ApplicationInfo->nativeLibraryDir:Ljava/lang/String;":
			return `return new StringObject(vm, "/data/app/~~cap==/" + packageName + "/lib/arm64");`, "App native library directory.", true
		case "android/content/pm/ApplicationInfo->packageName:Ljava/lang/String;":
			return `return new StringObject(vm, packageName);`, "ApplicationInfo.packageName.", true
		case "java/io/File->getAbsolutePath()Ljava/lang/String;", "java/io/File->getPath()Ljava/lang/String;":
			return `Object val = dvmObject.getValue();
            return new StringObject(vm, val != null ? val.toString() : "/data/user/0/" + packageName);`, "Returns wrapped File path.", true
		case "java/io/File-><init>(Ljava/lang/String;)V":
			if callback == CallbackNewObjectV {
				return `String path = vaList.getObjectArg(0).getValue().toString();
            return dvmClass.newObject(path);`, "Constructs synthetic File holding pathname.", true
			}
		case "android/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;":
			return `return new StringObject(vm, "352099001761481");`, "Synthetic IMEI for TelephonyManager.getDeviceId().", true
		case "android/telephony/TelephonyManager->getSubscriberId()Ljava/lang/String;":
			return `return new StringObject(vm, "310260000000000");`, "Synthetic IMSI for TelephonyManager.getSubscriberId().", true
		case "android/telephony/TelephonyManager->getNetworkOperatorName()Ljava/lang/String;":
			return `return new StringObject(vm, "T-Mobile");`, "Synthetic carrier name.", true
		case "android/telephony/TelephonyManager->getSimOperator()Ljava/lang/String;":
			return `return new StringObject(vm, "310260");`, "Synthetic MCC+MNC.", true
		case "android/app/ActivityThread->currentActivityThread()Landroid/app/ActivityThread;":
			if callback == CallbackCallStaticObjectMethodV {
				return `return dvmClass.newObject(null);`, "Provides stub ActivityThread.", true
			}
		case "android/app/ActivityThread->getApplication()Landroid/app/Application;":
			return `return vm.resolveClass("android/app/Application", vm.resolveClass("android/content/Context")).newObject(null);`, "Provides Application extending Context.", true
		case "android/content/pm/PackageInfo->versionName:Ljava/lang/String;":
			return `return new StringObject(vm, "1.0.0");`, "Synthetic app versionName.", true
		case "java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;":
			return `String key = vaList.getObjectArg(0).getValue().toString();
            if ("http.agent".equals(key)) {
                return new StringObject(vm, "Dalvik/2.1.0 (Linux; U; Android 13; Pixel 7 Build/TQ3A.230901.001)");
            }
            return new StringObject(vm, System.getProperty(key, ""));`, "Forwards JVM system property with realistic Android http.agent.", true
		}

		// Secondary heuristics by class/member
		if cls == "android/telephony/TelephonyManager" && strings.HasSuffix(desc, "Ljava/lang/String;") {
			return `return new StringObject(vm, "");`, "Fallback TelephonyManager string stub.", true
		}
		if cls == "android/content/pm/ApplicationInfo" && strings.HasSuffix(desc, "Ljava/lang/String;") {
			return `return new StringObject(vm, "/data/user/0/" + packageName);`, "Fallback ApplicationInfo path field.", true
		}
	}

	if isIntCB {
		switch sig {
		case "android/telephony/TelephonyManager->getNetworkType()I":
			return `return 13; // TelephonyManager.NETWORK_TYPE_LTE`, "Reports LTE network type.", true
		case "android/content/pm/PackageInfo->versionCode:I":
			return `return 10000;`, "Synthetic app versionCode.", true
		}
	}

	if isBoolCB {
		switch sig {
		case "java/io/File->exists()Z":
			return `return true;`, "Reports synthetic File as existing.", true
		case "java/io/File->isDirectory()Z":
			return `return true;`, "Reports synthetic File path as directory.", true
		case "android/os/Debug->isDebuggerConnected()Z":
			return `return false;`, "Reports no debugger attached.", true
		}
	}

	// Generic fallback based on callback type and return descriptor
	switch callback {
	case CallbackCallIntMethodV, CallbackGetIntField:
		return `return 0; // TODO: replace with observed int value for ` + sanitizeComment(sig), "Auto-generated integer stub.", false
	case CallbackCallBooleanMethodV:
		return `return false; // TODO: verify boolean return for ` + sanitizeComment(sig), "Auto-generated boolean stub.", false
	case CallbackNewObjectV:
		return `return dvmClass.newObject(null); // TODO: capture constructor arguments for ` + sanitizeComment(sig), "Auto-generated constructor stub.", false
	case CallbackResolveClass:
		return fmt.Sprintf(`vm.resolveClass(%s);`, javaQuote(cls)), "Pre-register custom Java class in VM.", false
	default:
		retType := extractReturnDescriptor(desc)
		switch {
		case retType == "Ljava/lang/String;":
			return `return new StringObject(vm, ""); // TODO: populate string for ` + sanitizeComment(sig), "Auto-generated String stub.", false
		case retType == "[B":
			return `return new ByteArray(vm, new byte[0]); // TODO: populate bytes for ` + sanitizeComment(sig), "Auto-generated byte[] stub.", false
		case strings.HasPrefix(retType, "L") && strings.HasSuffix(retType, ";"):
			retCls := strings.TrimSuffix(strings.TrimPrefix(retType, "L"), ";")
			return fmt.Sprintf(`return vm.resolveClass(%s).newObject(null); // TODO: stub %s`, javaQuote(retCls), sanitizeComment(sig)), "Auto-generated DvmObject stub.", false
		default:
			return superCallFallback(callback, sig), "Generic fallback stub.", false
		}
	}
}

func superCallFallback(callback, sig string) string {
	cmt := sanitizeComment(sig)
	switch callback {
	case CallbackCallStaticObjectMethodV, CallbackNewObjectV:
		return fmt.Sprintf("return super.%s(vm, dvmClass, signature, vaList); // TODO: implement %s", callback, cmt)
	case CallbackGetStaticObjectField:
		return fmt.Sprintf("return super.getStaticObjectField(vm, dvmClass, signature); // TODO: implement %s", cmt)
	case CallbackGetObjectField:
		return fmt.Sprintf("return super.getObjectField(vm, dvmObject, signature); // TODO: implement %s", cmt)
	case CallbackGetIntField:
		return fmt.Sprintf("return super.getIntField(vm, dvmObject, signature); // TODO: implement %s", cmt)
	default:
		return fmt.Sprintf("return super.%s(vm, dvmObject, signature, vaList); // TODO: implement %s", callback, cmt)
	}
}

func extractReturnDescriptor(desc string) string {
	if idx := strings.LastIndexByte(desc, ')'); idx >= 0 && idx+1 < len(desc) {
		return desc[idx+1:]
	}
	return desc
}

func suggestFileContent(path string) (content, note string) {
	switch path {
	case "/proc/self/cmdline":
		return "com.example.app\x00", "Process command line (NUL-terminated package name)."
	case "/proc/self/status":
		return "Name:\tcom.example.app\nState:\tR (running)\nTracerPid:\t0\nUid:\t10240\t10240\t10240\t10240\n", "Clean /proc/self/status with TracerPid: 0."
	case "/proc/self/maps":
		return "12c00000-13000000 rw-p 00000000 00:00 0          [anon:dalvik-main space]\n", "Minimal clean memory map."
	case "/proc/cpuinfo":
		return "Processor\t: AArch64 Processor rev 1 (aarch64)\nHardware\t: Qualcomm Technologies, Inc SM8450\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n", "Realistic ARM64 /proc/cpuinfo."
	case "/proc/version":
		return "Linux version 5.10.149-android13-4-00001-g12345678 (build-user@build-host) (Android clang) #1 SMP PREEMPT\n", "Android 13 kernel banner."
	case "/system/build.prop":
		return "ro.build.version.release=13\nro.build.version.sdk=33\nro.product.model=Pixel 7\nro.product.brand=google\nro.build.tags=release-keys\n", "Minimal /system/build.prop properties."
	case "/sys/devices/system/cpu/online":
		return "0-7\n", "8-core CPU topology."
	default:
		if strings.HasPrefix(path, "/proc/") {
			return "0\n", "Synthetic procfs placeholder; replace with device capture if parsed strictly."
		}
		return "", "Synthetic empty file; populate with real file pulled from device via adb."
	}
}

func suggestSysPropValue(key string) (val, note string) {
	switch key {
	case "ro.build.fingerprint":
		return "google/panther/panther:13/TQ3A.230901.001/10750268:user/release-keys", "Device build fingerprint."
	case "ro.build.version.release":
		return "13", "Android release version."
	case "ro.build.version.sdk":
		return "33", "Android API level."
	case "ro.build.tags":
		return "release-keys", "Release build signing tags."
	case "ro.build.type":
		return "user", "Production user build type."
	case "ro.product.model":
		return "Pixel 7", "Device model."
	case "ro.product.brand":
		return "google", "Device brand."
	case "ro.product.manufacturer":
		return "Google", "Device manufacturer."
	case "ro.product.device", "ro.product.name":
		return "panther", "Device codename."
	case "ro.product.cpu.abi":
		return "arm64-v8a", "Primary ABI."
	case "ro.product.cpu.abilist":
		return "arm64-v8a,armeabi-v7a,armeabi", "Supported ABIs."
	case "ro.hardware":
		return "panther", "Hardware identifier."
	case "ro.debuggable":
		return "0", "Non-debuggable production build."
	case "ro.secure":
		return "1", "Secure production property."
	case "ro.boot.verifiedbootstate":
		return "green", "Locked verified boot state."
	case "ro.boot.flash.locked":
		return "1", "Locked bootloader indicator."
	case "ro.kernel.qemu":
		return "0", "Physical device (non-emulator)."
	case "persist.sys.timezone":
		return "UTC", "System timezone."
	case "persist.sys.locale":
		return "en-US", "System locale."
	default:
		return "", "Unknown property key; capture real value with GenerateFridaEnvSnapshotScript."
	}
}

func renderAbstractJniSnippet(items []MissingJNIItem) string {
	grouped := make(map[string][]MissingJNIItem)
	for _, it := range items {
		grouped[it.Callback] = append(grouped[it.Callback], it)
	}
	if len(grouped) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("// ─── Auto-Synthesized Unidbg AbstractJni Overrides ───────────────────\n")
	b.WriteString("// Paste inside your class extending AbstractJni.\n")
	b.WriteString("private final String packageName = \"com.example.app\";\n")
	b.WriteString("private static final String ANDROID_ID = \"9774d56d682e549c\";\n")
	b.WriteString("private static final String SIGNING_CERT_HEX = \"30820122300d06092a864886f70d0101010500\";\n\n")

	order := []string{
		CallbackCallObjectMethodV,
		CallbackCallStaticObjectMethodV,
		CallbackGetStaticObjectField,
		CallbackGetObjectField,
		CallbackGetIntField,
		CallbackCallIntMethodV,
		CallbackCallBooleanMethodV,
		CallbackNewObjectV,
	}

	needsHexToBytes := false
	for _, it := range items {
		if strings.Contains(it.SuggestedCode, "hexToBytes(") {
			needsHexToBytes = true
			break
		}
	}

	for _, cb := range order {
		list := grouped[cb]
		if len(list) == 0 {
			continue
		}
		writeAbstractJniMethod(&b, cb, list)
	}

	if resList := grouped[CallbackResolveClass]; len(resList) > 0 {
		b.WriteString("// Pre-register resolved classes during VM setup:\n")
		b.WriteString("public void registerMissingClasses(VM vm) {\n")
		for _, it := range resList {
			fmt.Fprintf(&b, "    vm.resolveClass(%s);\n", javaQuote(it.ClassName))
		}
		b.WriteString("}\n\n")
	}

	if needsHexToBytes {
		b.WriteString(`private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i + 1 < len; i += 2) {
        out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
    }
    return out;
}
`)
	}

	return strings.TrimRight(b.String(), "\n")
}

func writeAbstractJniMethod(b *strings.Builder, cb string, items []MissingJNIItem) {
	switch cb {
	case CallbackCallObjectMethodV:
		b.WriteString("@Override\npublic DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {\n")
		b.WriteString("    switch (signature) {\n")
		for _, it := range items {
			fmt.Fprintf(b, "        case %s:\n            %s\n", javaQuote(it.Signature), it.SuggestedCode)
		}
		b.WriteString("        default:\n            return super.callObjectMethodV(vm, dvmObject, signature, vaList);\n    }\n}\n\n")

	case CallbackCallStaticObjectMethodV:
		b.WriteString("@Override\npublic DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {\n")
		b.WriteString("    switch (signature) {\n")
		for _, it := range items {
			fmt.Fprintf(b, "        case %s:\n            %s\n", javaQuote(it.Signature), it.SuggestedCode)
		}
		b.WriteString("        default:\n            return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);\n    }\n}\n\n")

	case CallbackGetStaticObjectField:
		b.WriteString("@Override\npublic DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {\n")
		b.WriteString("    switch (signature) {\n")
		for _, it := range items {
			fmt.Fprintf(b, "        case %s:\n            %s\n", javaQuote(it.Signature), it.SuggestedCode)
		}
		b.WriteString("        default:\n            return super.getStaticObjectField(vm, dvmClass, signature);\n    }\n}\n\n")

	case CallbackGetObjectField:
		b.WriteString("@Override\npublic DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {\n")
		b.WriteString("    switch (signature) {\n")
		for _, it := range items {
			fmt.Fprintf(b, "        case %s:\n            %s\n", javaQuote(it.Signature), it.SuggestedCode)
		}
		b.WriteString("        default:\n            return super.getObjectField(vm, dvmObject, signature);\n    }\n}\n\n")

	case CallbackGetIntField:
		b.WriteString("@Override\npublic int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {\n")
		b.WriteString("    switch (signature) {\n")
		for _, it := range items {
			fmt.Fprintf(b, "        case %s:\n            %s\n", javaQuote(it.Signature), it.SuggestedCode)
		}
		b.WriteString("        default:\n            return super.getIntField(vm, dvmObject, signature);\n    }\n}\n\n")

	case CallbackCallIntMethodV:
		b.WriteString("@Override\npublic int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {\n")
		b.WriteString("    switch (signature) {\n")
		for _, it := range items {
			fmt.Fprintf(b, "        case %s:\n            %s\n", javaQuote(it.Signature), it.SuggestedCode)
		}
		b.WriteString("        default:\n            return super.callIntMethodV(vm, dvmObject, signature, vaList);\n    }\n}\n\n")

	case CallbackCallBooleanMethodV:
		b.WriteString("@Override\npublic boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {\n")
		b.WriteString("    switch (signature) {\n")
		for _, it := range items {
			fmt.Fprintf(b, "        case %s:\n            %s\n", javaQuote(it.Signature), it.SuggestedCode)
		}
		b.WriteString("        default:\n            return super.callBooleanMethodV(vm, dvmObject, signature, vaList);\n    }\n}\n\n")

	case CallbackNewObjectV:
		b.WriteString("@Override\npublic DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {\n")
		b.WriteString("    switch (signature) {\n")
		for _, it := range items {
			fmt.Fprintf(b, "        case %s:\n            %s\n", javaQuote(it.Signature), it.SuggestedCode)
		}
		b.WriteString("        default:\n            return super.newObjectV(vm, dvmClass, signature, vaList);\n    }\n}\n\n")
	}
}

func renderIOResolverSnippet(files []MissingFileItem) string {
	if len(files) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("// ─── Auto-Synthesized Unidbg IOResolver<AndroidFileIO> ───────────────\n")
	b.WriteString("// Register via: emulator.getSyscallHandler().addIOResolver(this);\n")
	b.WriteString("@Override\n")
	b.WriteString("public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {\n")
	b.WriteString("    switch (pathname) {\n")
	for _, f := range files {
		fmt.Fprintf(&b, "        case %s:\n", javaQuote(f.Path))
		if f.Path == "/proc/self/cmdline" {
			b.WriteString("            return FileResult.success(new ByteArrayFileIO(oflags, pathname, (packageName + \"\\0\").getBytes(StandardCharsets.UTF_8)));\n")
		} else {
			fmt.Fprintf(&b, "            return FileResult.success(new ByteArrayFileIO(oflags, pathname, %s.getBytes(StandardCharsets.UTF_8)));\n", javaQuote(f.SuggestedContent))
		}
	}
	b.WriteString("        default:\n")
	b.WriteString("            return null;\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return strings.TrimRight(b.String(), "\n")
}

func renderSysPropHookSnippet(props []MissingSysPropItem) string {
	if len(props) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("// ─── Auto-Synthesized Unidbg SystemPropertyHook ──────────────────────\n")
	b.WriteString("SystemPropertyHook systemPropertyHook = new SystemPropertyHook(emulator);\n")
	b.WriteString("systemPropertyHook.setPropertyProvider(new SystemPropertyProvider() {\n")
	b.WriteString("    @Override\n")
	b.WriteString("    public String getProperty(String key) {\n")
	b.WriteString("        switch (key) {\n")
	for _, p := range props {
		fmt.Fprintf(&b, "            case %s:\n", javaQuote(p.Key))
		fmt.Fprintf(&b, "                return %s;\n", javaQuote(p.SuggestedValue))
	}
	b.WriteString("            default:\n")
	b.WriteString("                return null;\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("});\n")
	b.WriteString("emulator.getMemory().addHookListener(systemPropertyHook);\n")
	return strings.TrimRight(b.String(), "\n")
}

func renderCombinedStubSnippet(diag *UnidbgStubDiagnosis) string {
	var parts []string
	if diag.AbstractJniSnippet != "" {
		parts = append(parts, diag.AbstractJniSnippet)
	}
	if diag.IOResolverSnippet != "" {
		parts = append(parts, diag.IOResolverSnippet)
	}
	if diag.SysPropHookSnippet != "" {
		parts = append(parts, diag.SysPropHookSnippet)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n\n")
}

// GenerateFridaEnvSnapshotScript produces a syntax-verified Frida JS script
// that snapshots real Android device runtime properties (Build, Build.VERSION,
// PackageInfo + signing certificates, SystemProperties, ANDROID_ID, and app
// SharedPreferences) as structured JSON ready to feed into Unidbg stubs.
func GenerateFridaEnvSnapshotScript(targetPkg string) *GeneratedToolScript {
	pkg := strings.TrimSpace(targetPkg)
	if pkg == "" {
		pkg = "com.example.app"
	}

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap Unidbg Environment Snapshot Script (Frida) ──────────────────\n")
	fmt.Fprintf(&b, "// Target Package: %s\n", sanitizeComment(pkg))
	b.WriteString("// Captures real device Build, PackageInfo, signing cert, SystemProperties,\n")
	b.WriteString("// Settings.Secure.ANDROID_ID, and SharedPreferences for Unidbg stub hydration.\n\n")
	fmt.Fprintf(&b, "const TARGET_PACKAGE = %s;\n\n", jsQuote(pkg))
	b.WriteString(`function bytesToHex(bytes) {
    if (!bytes) return '';
    const out = [];
    for (let i = 0; i < bytes.length; i++) {
        out.push(((bytes[i] & 0xff) + 0x100).toString(16).slice(1));
    }
    return out.join('');
}

function sha256Hex(bytes) {
    try {
        const MessageDigest = Java.use('java.security.MessageDigest');
        const md = MessageDigest.getInstance('SHA-256');
        md.update(bytes);
        return bytesToHex(md.digest());
    } catch (_) {
        return '';
    }
}

function safeCall(fn, fallback) {
    try {
        const v = fn();
        return v === undefined || v === null ? fallback : v;
    } catch (_) {
        return fallback;
    }
}

function collectBuildInfo() {
    const Build = Java.use('android.os.Build');
    const Version = Java.use('android.os.Build$VERSION');
    const build = {
        MODEL: safeCall(function () { return String(Build.MODEL.value); }, ''),
        BRAND: safeCall(function () { return String(Build.BRAND.value); }, ''),
        MANUFACTURER: safeCall(function () { return String(Build.MANUFACTURER.value); }, ''),
        DEVICE: safeCall(function () { return String(Build.DEVICE.value); }, ''),
        PRODUCT: safeCall(function () { return String(Build.PRODUCT.value); }, ''),
        BOARD: safeCall(function () { return String(Build.BOARD.value); }, ''),
        HARDWARE: safeCall(function () { return String(Build.HARDWARE.value); }, ''),
        FINGERPRINT: safeCall(function () { return String(Build.FINGERPRINT.value); }, ''),
        ID: safeCall(function () { return String(Build.ID.value); }, ''),
        TAGS: safeCall(function () { return String(Build.TAGS.value); }, ''),
        TYPE: safeCall(function () { return String(Build.TYPE.value); }, ''),
        DISPLAY: safeCall(function () { return String(Build.DISPLAY.value); }, ''),
        BOOTLOADER: safeCall(function () { return String(Build.BOOTLOADER.value); }, ''),
        SUPPORTED_ABIS: safeCall(function () {
            const arr = Build.SUPPORTED_ABIS.value;
            const res = [];
            for (let i = 0; arr && i < arr.length; i++) {
                res.push(String(arr[i]));
            }
            return res;
        }, [])
    };
    const buildVersion = {
        RELEASE: safeCall(function () { return String(Version.RELEASE.value); }, ''),
        SDK_INT: safeCall(function () { return Number(Version.SDK_INT.value); }, 0),
        CODENAME: safeCall(function () { return String(Version.CODENAME.value); }, ''),
        INCREMENTAL: safeCall(function () { return String(Version.INCREMENTAL.value); }, ''),
        SECURITY_PATCH: safeCall(function () { return String(Version.SECURITY_PATCH.value); }, '')
    };
    return { build: build, buildVersion: buildVersion };
}

function collectSystemProperties() {
    const keys = [
        'ro.build.fingerprint',
        'ro.build.version.release',
        'ro.build.version.sdk',
        'ro.build.tags',
        'ro.build.type',
        'ro.build.display.id',
        'ro.product.model',
        'ro.product.brand',
        'ro.product.manufacturer',
        'ro.product.device',
        'ro.product.name',
        'ro.product.cpu.abi',
        'ro.product.cpu.abilist',
        'ro.hardware',
        'ro.debuggable',
        'ro.secure',
        'ro.boot.verifiedbootstate',
        'persist.sys.timezone',
        'persist.sys.locale'
    ];
    const props = {};
    try {
        const SysProps = Java.use('android.os.SystemProperties');
        for (let i = 0; i < keys.length; i++) {
            const k = keys[i];
            props[k] = safeCall(function () {
                return String(SysProps.get(k, ''));
            }, '');
        }
    } catch (_) {
        // SystemProperties hidden API unavailable on this runtime
    }
    return props;
}

function collectPackageAndCerts(ctx, pkgName) {
    const pm = ctx.getPackageManager();
    const Version = Java.use('android.os.Build$VERSION');
    const sdkInt = safeCall(function () { return Number(Version.SDK_INT.value); }, 0);
    // GET_SIGNING_CERTIFICATES (0x08000000) on API 28+, fallback GET_SIGNATURES (0x40)
    const flags = sdkInt >= 28 ? 0x08000000 : 0x40;
    let pInfo = safeCall(function () { return pm.getPackageInfo(pkgName, flags); }, null);
    if (!pInfo && flags !== 0x40) {
        pInfo = safeCall(function () { return pm.getPackageInfo(pkgName, 0x40); }, null);
    }
    if (!pInfo) {
        return { packageInfo: null, signatures: [] };
    }

    const appInfo = pInfo.applicationInfo.value;
    const packageInfo = {
        package_name: safeCall(function () { return String(pInfo.packageName.value); }, pkgName),
        version_name: safeCall(function () { return String(pInfo.versionName.value); }, ''),
        version_code: safeCall(function () {
            if (sdkInt >= 28 && pInfo.getLongVersionCode) {
                return Number(pInfo.getLongVersionCode());
            }
            return Number(pInfo.versionCode.value);
        }, 0),
        first_install_time: safeCall(function () { return Number(pInfo.firstInstallTime.value); }, 0),
        last_update_time: safeCall(function () { return Number(pInfo.lastUpdateTime.value); }, 0),
        source_dir: safeCall(function () { return appInfo ? String(appInfo.sourceDir.value) : ''; }, ''),
        data_dir: safeCall(function () { return appInfo ? String(appInfo.dataDir.value) : ''; }, ''),
        native_library_dir: safeCall(function () { return appInfo ? String(appInfo.nativeLibraryDir.value) : ''; }, '')
    };

    const signatures = [];
    const appendSigArray = function (sigArr) {
        if (!sigArr) return;
        for (let i = 0; i < sigArr.length; i++) {
            const rawBytes = safeCall(function () { return sigArr[i].toByteArray(); }, null);
            if (rawBytes) {
                signatures.push({
                    index: i,
                    sha256: sha256Hex(rawBytes),
                    hex: bytesToHex(rawBytes),
                    length: rawBytes.length
                });
            }
        }
    };

    if (sdkInt >= 28 && pInfo.signingInfo && pInfo.signingInfo.value) {
        const si = pInfo.signingInfo.value;
        appendSigArray(safeCall(function () { return si.getApkContentsSigners(); }, null));
    }
    if (signatures.length === 0 && pInfo.signatures && pInfo.signatures.value) {
        appendSigArray(pInfo.signatures.value);
    }

    return { packageInfo: packageInfo, signatures: signatures };
}

function collectSharedPreferences(ctx) {
    const prefsOut = {};
    try {
        const File = Java.use('java.io.File');
        const dataDir = String(ctx.getApplicationInfo().dataDir.value);
        const spDir = File.$new(dataDir + '/shared_prefs');
        if (!spDir.exists() || !spDir.isDirectory()) {
            return prefsOut;
        }
        const files = spDir.listFiles();
        if (!files) return prefsOut;
        for (let i = 0; i < files.length; i++) {
            const name = String(files[i].getName());
            if (!name.endsWith('.xml')) continue;
            const prefName = name.slice(0, -4);
            const sp = ctx.getSharedPreferences(prefName, 0);
            const allMap = sp.getAll();
            const entries = {};
            const it = allMap.entrySet().iterator();
            let count = 0;
            while (it.hasNext() && count < 200) {
                const entry = it.next();
                const k = String(entry.getKey());
                const v = entry.getValue();
                const s = v === null || v === undefined ? '' : String(v);
                entries[k] = s.length > 512 ? s.slice(0, 512) + '...(truncated)' : s;
                count++;
            }
            prefsOut[prefName] = entries;
        }
    } catch (e) {
        prefsOut._error = String(e);
    }
    return prefsOut;
}

Java.perform(function () {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const app = ActivityThread.currentApplication();
    const ctx = app ? app.getApplicationContext() : null;
    const activePkg = ctx ? safeCall(function () { return String(ctx.getPackageName()); }, TARGET_PACKAGE) : TARGET_PACKAGE;

    const buildBundle = collectBuildInfo();
    const sysProps = collectSystemProperties();
    const pkgBundle = ctx ? collectPackageAndCerts(ctx, activePkg) : { packageInfo: null, signatures: [] };
    const androidId = ctx ? safeCall(function () {
        const Secure = Java.use('android.provider.Settings$Secure');
        return String(Secure.getString(ctx.getContentResolver(), 'android_id'));
    }, '') : '';
    const sharedPrefs = ctx ? collectSharedPreferences(ctx) : {};

    send({
        type: 'unidbg_env_snapshot',
        target_package: activePkg,
        collected_at: new Date().toISOString(),
        build: buildBundle.build,
        build_version: buildBundle.buildVersion,
        package_info: pkgBundle.packageInfo,
        signatures: pkgBundle.signatures,
        system_properties: sysProps,
        android_id: androidId,
        shared_preferences: sharedPrefs
    });
});
`)

	return &GeneratedToolScript{
		Name:        fmt.Sprintf("Unidbg Env Snapshot · %s", pkg),
		Kind:        "frida_env_snapshot",
		Engine:      "frida",
		Language:    "javascript",
		FileName:    "unidbg_env_snapshot.js",
		Description: fmt.Sprintf("Frida script capturing real Android Build, PackageInfo, signing certificates, SystemProperties, ANDROID_ID, and SharedPreferences for %s.", pkg),
		Summary:     fmt.Sprintf("Generated Frida environment snapshot script for %s (emits type='unidbg_env_snapshot').", pkg),
		Code:        b.String(),
		Notes: []string{
			"Attach to the running target process with Frida and capture the JSON message with type == 'unidbg_env_snapshot'.",
			"Feed the captured Build, SystemProperties, ANDROID_ID, and certificate hex directly into your Unidbg AbstractJni and SystemPropertyHook stubs.",
		},
		Tags:        []string{"frida", "unidbg", "android", "env-snapshot"},
		GeneratedAt: nowRFC3339(),
	}
}

// --- Shared escaping helpers -------------------------------------------------

// javaQuote produces a safe single-line Java string literal, escaping quotes,
// backslashes (preventing JLS §3.3 Unicode escape breakout), control bytes,
// and Unicode line separators.
func javaQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 || r == 0x7f || r == 0x0085 || r == 0x2028 || r == 0x2029 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// jsQuote produces a safe single-line JavaScript string literal, escaping
// quotes, backslashes, all ASCII control chars (<0x20, 0x7f), and Unicode
// line terminators (U+0085, U+2028, U+2029).
func jsQuote(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else if r == 0x0085 || r == 0x2028 || r == 0x2029 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// sanitizeComment neutralizes comment breakout sequences across Java (JLS §3.3
// \uXXXX), JavaScript (U+2028/U+2029), Python (NUL bytes & newlines), and block
// comment terminators (*/).
func sanitizeComment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f || r == 0x0085 || r == 0x2028 || r == 0x2029:
			b.WriteByte(' ')
		case r == '\\':
			// Defang backslash so Java JLS §3.3 \u000a / \u000d cannot terminate // comments.
			b.WriteByte('/')
		default:
			b.WriteRune(r)
		}
	}
	return strings.ReplaceAll(strings.TrimSpace(b.String()), "*/", "* /")
}
