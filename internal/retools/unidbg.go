package retools

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	javaPublicClassRe = regexp.MustCompile(`public\s+class\s+([A-Za-z_][A-Za-z0-9_]*)`)
	javaAnyClassRe    = regexp.MustCompile(`\bclass\s+([A-Za-z_][A-Za-z0-9_]*)`)
	javaPackageRe     = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*;`)
	nonIdentRe        = regexp.MustCompile(`[^A-Za-z0-9_]`)
)

// BuiltinUnidbgProjects returns curated Unidbg Android JNI emulation starter templates.
func BuiltinUnidbgProjects() []REProject {
	std := GenerateUnidbgHarness(GenerateOptions{
		PackageName:     "com.example.app",
		APKPath:         "/path/to/app.apk",
		BinaryPath:      "/path/to/libnative.so",
		TargetClass:     "com/example/app/NativeSigner",
		TargetMethod:    "nativeSign",
		MethodSignature: "(Ljava/lang/String;J)Ljava/lang/String;",
		Args:            []string{"payload=hello&ts=1700000000"},
		Arch:            "arm64",
		ClassName:       "CapUnidbgHarness",
	})
	httpSrv := GenerateUnidbgHarness(GenerateOptions{
		PackageName:     "com.example.app",
		APKPath:         "/path/to/app.apk",
		BinaryPath:      "/path/to/libnative.so",
		TargetClass:     "com/example/app/NativeSigner",
		TargetMethod:    "nativeSign",
		MethodSignature: "(Ljava/lang/String;J)Ljava/lang/String;",
		Args:            []string{"payload=hello&ts=1700000000"},
		Arch:            "arm64",
		HTTPServerMode:  true,
		HTTPPort:        8899,
		ClassName:       "CapUnidbgHttpSigner",
	})

	return []REProject{
		{
			ID:           "builtin:unidbg-jni-sign",
			Name:         "Unidbg Android ARM64 JNI Emulator",
			Engine:       EngineUnidbg,
			Description:  "Standalone 64-bit Unidbg AndroidEmulatorBuilder harness with DalvikModule, AbstractJni stubs, JNI_OnLoad invocation, and [CAP_RE] JSON output.",
			BinaryPath:   std.BinaryPath,
			APKPath:      std.APKPath,
			TargetClass:  std.TargetClass,
			TargetMethod: std.TargetMethod,
			Args:         std.Project.Args,
			Code:         std.Code,
			Builtin:      true,
			Tags:         []string{"unidbg", "android", "jni", "arm64", "sign"},
		},
		{
			ID:           "builtin:unidbg-http-signer",
			Name:         "Unidbg Embedded HTTP Signer Server",
			Engine:       EngineUnidbg,
			Description:  "Runs a warm Unidbg JNI instance behind a zero-dependency Java HttpServer (POST /sign, GET /health) ready to plug into cap's API Gateway.",
			BinaryPath:   httpSrv.BinaryPath,
			APKPath:      httpSrv.APKPath,
			TargetClass:  httpSrv.TargetClass,
			TargetMethod: httpSrv.TargetMethod,
			Args:         httpSrv.Project.Args,
			Code:         httpSrv.Code,
			Builtin:      true,
			Tags:         []string{"unidbg", "http-server", "signer", "gateway", "jni"},
		},
	}
}

// GenerateUnidbgHarness synthesizes a runnable Java Unidbg Android JNI emulation
// harness (optionally exposing an embedded HTTP signing endpoint when
// opts.HTTPServerMode is true).
func GenerateUnidbgHarness(opts GenerateOptions) *GeneratedHarness {
	pkgName := firstNonEmpty(opts.PackageName, "com.example.app")
	apkPath := firstNonEmpty(opts.APKPath, "/path/to/app.apk")
	soPath := firstNonEmpty(opts.BinaryPath, opts.SOFile, "/path/to/libnative.so")
	targetClass := normalizeJNIDalvikClass(firstNonEmpty(opts.TargetClass, strings.ReplaceAll(pkgName, ".", "/")+"/NativeSigner"))
	targetMethod := firstNonEmpty(opts.TargetMethod, "nativeSign")
	sig := strings.TrimSpace(opts.MethodSignature)
	if sig == "" {
		sig = "(Ljava/lang/String;)Ljava/lang/String;"
	}
	if !strings.HasPrefix(sig, "(") {
		sig = "(" + sig + ")"
	}
	methodAndSig := targetMethod + sig

	arch := normalizeEmulationArch(opts.Arch, soPath)
	builderCall := "AndroidEmulatorBuilder.for64Bit()"
	if arch == "arm" {
		builderCall = "AndroidEmulatorBuilder.for32Bit()"
	}

	className := sanitizeJavaClassName(opts.ClassName)
	if className == "" {
		if opts.HTTPServerMode {
			className = "CapUnidbgHttpSigner"
		} else {
			className = "CapUnidbgHarness"
		}
	}

	httpPort := opts.HTTPPort
	if httpPort <= 0 {
		httpPort = 8899
	}

	sampleArg := "test_payload"
	if len(opts.Args) > 0 && strings.TrimSpace(opts.Args[0]) != "" {
		sampleArg = opts.Args[0]
	}

	invokeArgsExpr := buildUnidbgCallArgs(sig, sampleArg)
	code := renderUnidbgJavaSource(unidbgTemplateParams{
		ClassName:      className,
		BuilderCall:    builderCall,
		PackageName:    pkgName,
		APKPath:        apkPath,
		SOPath:         soPath,
		TargetClass:    targetClass,
		TargetMethod:   targetMethod,
		MethodAndSig:   methodAndSig,
		TargetSymbol:   opts.TargetSymbol,
		TargetAddr:     opts.TargetAddr,
		SampleArg:      sampleArg,
		InvokeArgsExpr: invokeArgsExpr,
		HTTPServerMode: opts.HTTPServerMode,
		HTTPPort:       httpPort,
	})

	modeLabel := "JNI Emulator"
	if opts.HTTPServerMode {
		modeLabel = fmt.Sprintf("HTTP Signer Server (:%d)", httpPort)
	}
	name := fmt.Sprintf("Unidbg %s · %s.%s", modeLabel, filepath.Base(targetClass), targetMethod)
	desc := fmt.Sprintf("Unidbg (%s) Java harness emulating %s.%s in %s.", arch, targetClass, methodAndSig, filepath.Base(soPath))

	tags := []string{"unidbg", arch, "jni", "generated"}
	if opts.HTTPServerMode {
		tags = append(tags, "http-server", "signer")
	}

	proj := REProject{
		Name:         name,
		Engine:       EngineUnidbg,
		Description:  desc,
		BinaryPath:   soPath,
		APKPath:      apkPath,
		TargetClass:  targetClass,
		TargetMethod: targetMethod,
		TargetSymbol: opts.TargetSymbol,
		TargetAddr:   opts.TargetAddr,
		Args:         opts.Args,
		Code:         code,
		Tags:         tags,
	}

	notes := []string{
		fmt.Sprintf("Target ABI/Architecture: %s (%s)", arch, builderCall),
		"Adjust AbstractJni stubs below if the .so queries additional Java fields, Context, or PackageManager signatures.",
	}
	if opts.HTTPServerMode {
		notes = append(notes, fmt.Sprintf("HTTP Signer exposes GET http://127.0.0.1:%d/health and POST http://127.0.0.1:%d/sign", httpPort, httpPort))
	}

	return &GeneratedHarness{
		Name:         name,
		Engine:       EngineUnidbg,
		Language:     "java",
		FileName:     className + ".java",
		Description:  desc,
		Summary:      fmt.Sprintf("Generated Unidbg %s harness (%s) for %s!%s", arch, className+".java", filepath.Base(soPath), targetMethod),
		Code:         code,
		Project:      proj,
		BinaryPath:   soPath,
		APKPath:      apkPath,
		TargetClass:  targetClass,
		TargetMethod: targetMethod,
		TargetSymbol: opts.TargetSymbol,
		TargetAddr:   opts.TargetAddr,
		Notes:        notes,
		GeneratedAt:  nowRFC3339(),
	}
}

type unidbgTemplateParams struct {
	ClassName      string
	BuilderCall    string
	PackageName    string
	APKPath        string
	SOPath         string
	TargetClass    string
	TargetMethod   string
	MethodAndSig   string
	TargetSymbol   string
	TargetAddr     string
	SampleArg      string
	InvokeArgsExpr string
	HTTPServerMode bool
	HTTPPort       int
}

func renderUnidbgJavaSource(p unidbgTemplateParams) string {
	var b strings.Builder

	b.WriteString("// ─── cap Auto-Generated Unidbg Android JNI Harness ───────────────────\n")
	fmt.Fprintf(&b, "// Package: %s\n", p.PackageName)
	fmt.Fprintf(&b, "// Library: %s\n", p.SOPath)
	fmt.Fprintf(&b, "// Target:  %s -> %s\n", p.TargetClass, p.MethodAndSig)
	if p.TargetSymbol != "" || p.TargetAddr != "" {
		fmt.Fprintf(&b, "// Export:  %s @ %s\n", p.TargetSymbol, p.TargetAddr)
	}
	b.WriteString("\n")
	b.WriteString(`import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VarArg;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
`)
	if p.HTTPServerMode {
		b.WriteString(`import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
`)
	}

	fmt.Fprintf(&b, "\npublic class %s extends AbstractJni {\n", p.ClassName)
	fmt.Fprintf(&b, "    private static final String PROCESS_NAME = %s;\n", javaQuote(p.PackageName))
	fmt.Fprintf(&b, "    private static final String APK_PATH = envOr(\"CAP_RE_APK\", %s);\n", javaQuote(p.APKPath))
	fmt.Fprintf(&b, "    private static final String SO_PATH = envOr(\"CAP_RE_BINARY\", %s);\n", javaQuote(p.SOPath))
	fmt.Fprintf(&b, "    private static final String TARGET_CLASS = %s;\n", javaQuote(p.TargetClass))
	fmt.Fprintf(&b, "    private static final String TARGET_METHOD_SIG = %s;\n", javaQuote(p.MethodAndSig))
	if p.HTTPServerMode {
		fmt.Fprintf(&b, "    private static final int HTTP_PORT = Integer.parseInt(envOr(\"CAP_RE_HTTP_PORT\", \"%d\"));\n", p.HTTPPort)
	}

	b.WriteString(`
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DalvikModule dm;
    private final DvmClass targetClass;

    public ` + p.ClassName + `() {
        this.emulator = ` + p.BuilderCall + `
                .setProcessName(PROCESS_NAME)
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        File apkFile = new File(APK_PATH);
        this.vm = apkFile.isFile()
                ? emulator.createDalvikVM(apkFile)
                : emulator.createDalvikVM();
        this.vm.setVerbose(false);
        this.vm.setJni(this);

        File soFile = new File(SO_PATH);
        if (!soFile.isFile()) {
            throw new IllegalStateException("Native library not found: " + SO_PATH);
        }
        this.dm = this.vm.loadLibrary(soFile, true);
        this.dm.callJNI_OnLoad(emulator);
        this.targetClass = this.vm.resolveClass(TARGET_CLASS);
    }

    public synchronized String invokeTarget(String input) {
        DvmObject<?> ret = targetClass.callStaticJniMethodObject(
                emulator,
                TARGET_METHOD_SIG,
                ` + p.InvokeArgsExpr + `
        );
        if (ret == null || ret.getValue() == null) {
            return "";
        }
        Object val = ret.getValue();
        if (val instanceof byte[]) {
            return bytesToHex((byte[]) val);
        }
        return String.valueOf(val);
    }

    // ── Common AbstractJni Environment Stubs ─────────────────────────────
    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("android/os/Build->MODEL:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "Pixel 8 Pro");
        }
        if ("android/os/Build->BRAND:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "google");
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if ("android/content/Context->getPackageName()Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, PROCESS_NAME);
        }
        if ("java/lang/String->getBytes()[B".equals(signature)) {
            String s = String.valueOf(dvmObject.getValue());
            return new ByteArray(vm, s.getBytes(StandardCharsets.UTF_8));
        }
        return super.callObjectMethodV(vm, dvmObject, signature, varArg);
    }

    public void close() throws IOException {
        emulator.close();
    }

    private static String envOr(String key, String fallback) {
        String v = System.getenv(key);
        return (v != null && !v.trim().isEmpty()) ? v.trim() : fallback;
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
`)

	if p.HTTPServerMode {
		b.WriteString(`
    public void serveHttp() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", HTTP_PORT), 0);
        server.createContext("/health", exchange -> {
            writeJson(exchange, 200, "{\"ok\":true,\"engine\":\"unidbg\",\"target\":\"" + jsonEscape(TARGET_CLASS) + "\"}");
        });
        server.createContext("/sign", exchange -> {
            try {
                byte[] reqBytes = readAll(exchange.getRequestBody());
                String payload = new String(reqBytes, StandardCharsets.UTF_8).trim();
                String result = invokeTarget(payload);
                String body = "{\"ok\":true,\"sign\":\"" + jsonEscape(result) + "\"}";
                System.out.println("[CAP_RE] {\"kind\":\"signature\",\"input\":\"" + jsonEscape(payload) + "\",\"sign\":\"" + jsonEscape(result) + "\"}");
                writeJson(exchange, 200, body);
            } catch (Throwable t) {
                writeJson(exchange, 500, "{\"ok\":false,\"error\":\"" + jsonEscape(t.toString()) + "\"}");
            }
        });
        server.start();
        String url = "http://127.0.0.1:" + HTTP_PORT + "/sign";
        System.out.println("[CAP_RE] {\"kind\":\"server\",\"status\":\"listening\",\"url\":\"" + url + "\"}");
        System.out.flush();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) >= 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static void writeJson(HttpExchange ex, int status, String json) throws IOException {
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, data.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(data);
        }
    }

    public static void main(String[] args) throws Exception {
        ` + p.ClassName + ` signer = new ` + p.ClassName + `();
        signer.serveHttp();
        Thread.currentThread().join();
    }
}
`)
	} else {
		fmt.Fprintf(&b, `
    public static void main(String[] args) throws Exception {
        String input = args.length > 0 ? args[0] : %s;
        %s harness = new %s();
        try {
            String result = harness.invokeTarget(input);
            System.out.println("[CAP_RE] {\"kind\":\"signature\",\"target\":\"" + jsonEscape(TARGET_CLASS + "." + TARGET_METHOD_SIG) + "\",\"input\":\"" + jsonEscape(input) + "\",\"result\":\"" + jsonEscape(result) + "\"}");
        } finally {
            harness.close();
        }
    }
}
`, javaQuote(p.SampleArg), p.ClassName, p.ClassName)
	}

	return b.String()
}

func buildUnidbgCallArgs(sig, sampleArg string) string {
	// Parse JVM parameter descriptors between '(' and ')'.
	openIdx := strings.IndexByte(sig, '(')
	closeIdx := strings.IndexByte(sig, ')')
	if openIdx < 0 || closeIdx <= openIdx+1 {
		return "new StringObject(vm, input)"
	}
	params := sig[openIdx+1 : closeIdx]
	var args []string
	for i := 0; i < len(params); {
		switch params[i] {
		case 'L':
			semi := strings.IndexByte(params[i:], ';')
			if semi < 0 {
				i = len(params)
				continue
			}
			desc := params[i : i+semi+1]
			i += semi + 1
			if desc == "Ljava/lang/String;" {
				args = append(args, "new StringObject(vm, input)")
			} else {
				args = append(args, "vm.resolveClass("+javaQuote(strings.TrimSuffix(strings.TrimPrefix(desc, "L"), ";"))+").newObject(null)")
			}
		case '[':
			if i+1 < len(params) && params[i+1] == 'B' {
				args = append(args, "new ByteArray(vm, input.getBytes(StandardCharsets.UTF_8))")
				i += 2
			} else if i+1 < len(params) && params[i+1] == 'L' {
				semi := strings.IndexByte(params[i:], ';')
				if semi < 0 {
					i = len(params)
				} else {
					i += semi + 1
				}
				args = append(args, "null")
			} else {
				i += 2
				args = append(args, "null")
			}
		case 'J':
			args = append(args, "System.currentTimeMillis() / 1000L")
			i++
		case 'I', 'S', 'B', 'C':
			args = append(args, "0")
			i++
		case 'Z':
			args = append(args, "true")
			i++
		case 'F':
			args = append(args, "0.0f")
			i++
		case 'D':
			args = append(args, "0.0d")
			i++
		default:
			i++
		}
	}
	if len(args) == 0 {
		return fmt.Sprintf("new StringObject(vm, %s)", javaQuote(sampleArg))
	}
	return strings.Join(args, ",\n                ")
}

func extractJavaClassName(code string) string {
	if m := javaPublicClassRe.FindStringSubmatch(code); len(m) >= 2 {
		return m[1]
	}
	if m := javaAnyClassRe.FindStringSubmatch(code); len(m) >= 2 {
		return m[1]
	}
	return "CapUnidbgHarness"
}

func extractJavaPackageName(code string) string {
	if m := javaPackageRe.FindStringSubmatch(code); len(m) >= 2 {
		return m[1]
	}
	return ""
}

func sanitizeJavaClassName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.TrimSuffix(s, ".java")
	s = nonIdentRe.ReplaceAllString(s, "")
	if s == "" {
		return ""
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "Cap" + s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func normalizeJNIDalvikClass(cls string) string {
	cls = strings.TrimSpace(cls)
	cls = strings.TrimPrefix(cls, "L")
	cls = strings.TrimSuffix(cls, ";")
	cls = strings.ReplaceAll(cls, ".", "/")
	return cls
}

func normalizeEmulationArch(arch, binaryPath string) string {
	low := strings.ToLower(strings.TrimSpace(arch))
	switch low {
	case "arm64", "aarch64", "arm64-v8a":
		return "arm64"
	case "arm", "armeabi", "armeabi-v7a", "thumb":
		return "arm"
	case "x86_64", "amd64":
		return "x86_64"
	case "x86", "i386", "i686":
		return "x86"
	}
	pathLow := strings.ToLower(binaryPath)
	switch {
	case strings.Contains(pathLow, "arm64-v8a"), strings.Contains(pathLow, "aarch64"), strings.Contains(pathLow, "arm64"):
		return "arm64"
	case strings.Contains(pathLow, "armeabi-v7a"), strings.Contains(pathLow, "armeabi"):
		return "arm"
	case strings.Contains(pathLow, "x86_64"), strings.Contains(pathLow, "amd64"):
		return "x86_64"
	case strings.Contains(pathLow, "/x86/"), strings.Contains(pathLow, "_x86_"):
		return "x86"
	default:
		return "arm64"
	}
}

func javaQuote(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\r", `\r`,
		"\t", `\t`,
	)
	return `"` + replacer.Replace(s) + `"`
}
