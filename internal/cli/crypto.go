package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/cryptolab"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/tui"
)

func newCryptoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "CryptoLab workbench (pipelines, payload ID, schema-less Protobuf, AES-128 DFA)",
		Long: `CyberChef-style cryptographic workbench, schema-less Protobuf inspector, and White-Box AES-128 DFA solver:

  ops         — List all supported composable codec, hash, cipher, and protobuf operations
  identify    — Auto-identify encodings, magic bytes, JWTs, entropy, and suggested recipes
  run         — Execute a single operation (--op) or multi-step JSON pipeline (--pipeline-json)
  protobuf    — Schema-less Protobuf wire decoder (--decode) and re-encoder (--encode-json)
  dfa         — Recover AES-128 Round-10 subkey & Master Key from Round-9 faulty ciphertexts
  dfa-script  — Generate a Unidbg (Java) or Qiling (Python) Round-9 DFA fault-injection harness

Examples:
  cap crypto ops --json
  cap crypto identify "SGVsbG8gV29ybGQ=" --json
  cap crypto run --op base64_encode --input "hello world"
  cap crypto run --pipeline-json ./recipe.json --input "68656c6c6f" --input-format hex
  cap crypto protobuf --decode "08 96 01 12 05 68 65 6c 6c 6f"
  cap crypto dfa --valid <32-hex> --fault <32-hex> --fault <32-hex> --json
  cap crypto dfa-script --engine unidbg --binary libwb.so -o WhiteboxDFA.java`,
	}

	cmd.AddCommand(
		newCryptoOpsCmd(),
		newCryptoIdentifyCmd(),
		newCryptoRunCmd(),
		newCryptoProtobufCmd(),
		newCryptoDFACmd(),
		newCryptoDFAScriptCmd(),
	)
	return cmd
}

func newCryptoOpsCmd() *cobra.Command {
	var (
		category string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "ops",
		Short: "List available CryptoLab pipeline operations and parameters",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			all := cryptolab.ListOperations()
			catFilter := strings.ToLower(strings.TrimSpace(category))
			ops := make([]cryptolab.OperationSpec, 0, len(all))
			for _, op := range all {
				if catFilter != "" && strings.ToLower(op.Category) != catFilter {
					continue
				}
				ops = append(ops, op)
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(ops)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.crypto.ops.title"), fmt.Sprintf("%d op(s)", len(ops)))
			}
			fmt.Fprintf(out, "%-24s %-13s %-22s %s\n", "NAME", "CATEGORY", "LABEL", "DESCRIPTION")
			for _, op := range ops {
				fmt.Fprintf(out, "%-24s %-13s %-22s %s\n",
					tui.Truncate(op.Name, 24), tui.Truncate(op.Category, 13),
					tui.Truncate(op.Label, 22), op.Description)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&category, "category", "", "filter by category (codec, compression, xor, hash, hmac, cipher, protobuf)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output OperationSpec JSON")
	return cmd
}

func newCryptoIdentifyCmd() *cobra.Command {
	var (
		filePath string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "identify [input]",
		Short: "Auto-identify payload encoding, magic headers, JWT claims, entropy, and recipes",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			var input string
			switch {
			case strings.TrimSpace(filePath) != "":
				raw, err := os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("read input file %s: %w", filePath, err)
				}
				input = string(raw)
			case len(args) == 1 && args[0] == "-":
				raw, err := io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("read stdin: %w", err)
				}
				input = string(raw)
			case len(args) == 1:
				input = args[0]
			default:
				return fmt.Errorf("input payload argument or --file is required")
			}

			res := cryptolab.IdentifyPayload(input)
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.crypto.identify.title"), fmt.Sprintf("%d chars", res.InputLen))
			}
			fmt.Fprintf(out, "Input Length: %d chars (%d bytes)  Printable UTF-8: %v\n",
				res.InputLen, res.DecodedByteLen, res.IsPrintableUTF8)
			fmt.Fprintf(out, "Entropy:      %.3f bits/byte (%s)\n", res.Entropy, res.EntropyClass)
			if len(res.Candidates) > 0 {
				fmt.Fprintln(out, "\nCandidates:")
				for _, c := range res.Candidates {
					fmt.Fprintf(out, "  - %-16s (%3.0f%%) %s", c.Format, c.Confidence*100, c.Label)
					if c.Details != "" {
						fmt.Fprintf(out, " — %s", c.Details)
					}
					fmt.Fprintln(out)
				}
			}
			if res.JWT != nil {
				fmt.Fprintf(out, "\nJWT (%s):\n  Header:  %s\n  Payload: %s\n",
					res.JWT.Algorithm, res.JWT.HeaderJSON, res.JWT.PayloadJSON)
			}
			if len(res.Recipes) > 0 {
				fmt.Fprintln(out, "\nRecommended Recipes:")
				for _, rec := range res.Recipes {
					fmt.Fprintf(out, "  - %s: %s\n", rec.Name, rec.Description)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&filePath, "file", "f", "", "read payload from file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output IdentifyResult JSON")
	return cmd
}

func newCryptoRunCmd() *cobra.Command {
	var (
		opName       string
		params       []string
		pipelineJSON string
		input        string
		filePath     string
		inputFormat  string
		outputFormat string
		jsonOut      bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a single CryptoLab operation or multi-step JSON pipeline",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			var req cryptolab.PipelineRequest
			if strings.TrimSpace(pipelineJSON) != "" {
				rawText := strings.TrimSpace(pipelineJSON)
				if !strings.HasPrefix(rawText, "{") && !strings.HasPrefix(rawText, "[") {
					data, err := os.ReadFile(rawText)
					if err != nil {
						return fmt.Errorf("read --pipeline-json %s: %w", rawText, err)
					}
					rawText = strings.TrimSpace(string(data))
				}
				if strings.HasPrefix(rawText, "[") {
					var steps []cryptolab.PipelineStep
					if err := json.Unmarshal([]byte(rawText), &steps); err != nil {
						return fmt.Errorf("parse pipeline steps JSON: %w", err)
					}
					req.Steps = steps
				} else {
					if err := json.Unmarshal([]byte(rawText), &req); err != nil {
						return fmt.Errorf("parse pipeline request JSON: %w", err)
					}
				}
			} else if strings.TrimSpace(opName) != "" {
				pMap := make(map[string]string, len(params))
				for _, kv := range params {
					k, v, ok := strings.Cut(kv, "=")
					if !ok || strings.TrimSpace(k) == "" {
						return fmt.Errorf("invalid --param %q (expected key=value)", kv)
					}
					pMap[strings.TrimSpace(k)] = v
				}
				req.Steps = []cryptolab.PipelineStep{{
					Op:     strings.TrimSpace(opName),
					Params: pMap,
				}}
			} else {
				return fmt.Errorf("either --op or --pipeline-json is required")
			}

			if strings.TrimSpace(filePath) != "" {
				raw, err := os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("read input file %s: %w", filePath, err)
				}
				req.Input = string(raw)
			} else if cmd.Flags().Changed("input") {
				if input == "-" {
					raw, err := io.ReadAll(cmd.InOrStdin())
					if err != nil {
						return fmt.Errorf("read stdin: %w", err)
					}
					req.Input = string(raw)
				} else {
					req.Input = input
				}
			}
			if cmd.Flags().Changed("input-format") || req.InputEncoding == "" {
				req.InputEncoding = strings.TrimSpace(inputFormat)
			}

			res := cryptolab.RunPipeline(req)
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return err
				}
				if !res.Success {
					return fmt.Errorf("pipeline failed at step %d: %s", res.FailedStep, res.Error)
				}
				return nil
			}
			if !res.Success {
				return fmt.Errorf("pipeline failed at step %d: %s", res.FailedStep, res.Error)
			}

			switch strings.ToLower(strings.TrimSpace(outputFormat)) {
			case "", "utf8", "text":
				fmt.Fprintln(out, res.OutputUTF8)
			case "hex":
				fmt.Fprintln(out, res.OutputHex)
			case "base64", "b64":
				fmt.Fprintln(out, res.OutputBase64)
			default:
				return fmt.Errorf("unsupported --output-format %q (expected utf8, hex, or base64)", outputFormat)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opName, "op", "", "single operation name (see 'cap crypto ops')")
	cmd.Flags().StringArrayVarP(&params, "param", "p", nil, "operation parameter key=value (repeatable, used with --op)")
	cmd.Flags().StringVar(&pipelineJSON, "pipeline-json", "", "JSON string or file path for PipelineRequest or []PipelineStep")
	cmd.Flags().StringVarP(&input, "input", "i", "", "input payload string (or - for stdin)")
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "read input payload from file")
	cmd.Flags().StringVar(&inputFormat, "input-format", "utf8", "input encoding: utf8, hex, or base64")
	cmd.Flags().StringVar(&outputFormat, "output-format", "utf8", "plain output format: utf8, hex, or base64")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output full PipelineResult JSON")
	return cmd
}

func decodeHexOrBase64ProtobufCLI(hexOrB64 string) (*cryptolab.ProtoMessageNode, error) {
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
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
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

func newCryptoProtobufCmd() *cobra.Command {
	var (
		decodePayload string
		encodeJSON    string
		jsonOut       bool
	)

	cmd := &cobra.Command{
		Use:   "protobuf",
		Short: "Decode raw Protobuf wire bytes without a .proto schema or re-encode from JSON AST",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if strings.TrimSpace(decodePayload) != "" && strings.TrimSpace(encodeJSON) != "" {
				return fmt.Errorf("specify either --decode or --encode-json, not both")
			}

			if strings.TrimSpace(encodeJSON) != "" {
				src := strings.TrimSpace(encodeJSON)
				var (
					raw []byte
					err error
				)
				switch {
				case src == "-":
					raw, err = io.ReadAll(cmd.InOrStdin())
				case strings.HasPrefix(src, "{"):
					raw = []byte(src)
				default:
					raw, err = os.ReadFile(src)
				}
				if err != nil {
					return fmt.Errorf("read protobuf AST JSON: %w", err)
				}
				var node cryptolab.ProtoMessageNode
				if err := json.Unmarshal(raw, &node); err != nil {
					return fmt.Errorf("parse ProtoMessageNode JSON: %w", err)
				}
				encoded, err := cryptolab.EncodeProtobufRaw(&node)
				if err != nil {
					return err
				}
				hexStr := hex.EncodeToString(encoded)
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]any{
						"hex":      hexStr,
						"base64":   base64.StdEncoding.EncodeToString(encoded),
						"byte_len": len(encoded),
					})
				}
				fmt.Fprintln(out, hexStr)
				return nil
			}

			if strings.TrimSpace(decodePayload) != "" {
				payload := strings.TrimSpace(decodePayload)
				if payload == "-" {
					raw, err := io.ReadAll(cmd.InOrStdin())
					if err != nil {
						return fmt.Errorf("read stdin: %w", err)
					}
					payload = string(raw)
				}
				node, err := decodeHexOrBase64ProtobufCLI(payload)
				if err != nil {
					return err
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(node)
			}

			return fmt.Errorf("either --decode <hex-or-b64> or --encode-json <file> is required")
		},
	}

	cmd.Flags().StringVar(&decodePayload, "decode", "", "raw Protobuf payload as hex or Base64 (or - for stdin)")
	cmd.Flags().StringVar(&encodeJSON, "encode-json", "", "ProtoMessageNode JSON file path, raw JSON, or - for stdin")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newCryptoDFACmd() *cobra.Command {
	var (
		validHex     string
		faults       []string
		faultFile    string
		plaintextHex string
		jsonOut      bool
	)

	cmd := &cobra.Command{
		Use:   "dfa",
		Short: "Recover an AES-128 Master Key via Round-9 Differential Fault Analysis (DFA)",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			allFaults := append([]string(nil), faults...)
			if strings.TrimSpace(faultFile) != "" {
				raw, err := os.ReadFile(faultFile)
				if err != nil {
					return fmt.Errorf("read --fault-file %s: %w", faultFile, err)
				}
				for _, line := range strings.Split(string(raw), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					allFaults = append(allFaults, line)
				}
			}

			res, err := cryptolab.SolveAES128DFA(cryptolab.DFARequest{
				ValidCiphertextHex:   validHex,
				FaultyCiphertextsHex: allFaults,
				PlaintextHex:         plaintextHex,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.crypto.dfa.title"), fmt.Sprintf("%d/%d faults", res.UsableFaults, res.TotalFaultsInput))
			}
			fmt.Fprintf(out, "Solved:     %v (verified_with_plaintext=%v, elapsed=%dus)\n",
				res.Solved, res.VerifiedWithPlaintext, res.ElapsedUS)
			if res.MasterKeyHex != "" {
				fmt.Fprintf(out, "Master Key: %s\n", res.MasterKeyHex)
			}
			if res.Round10KeyHex != "" {
				fmt.Fprintf(out, "Round-10 K: %s\n", res.Round10KeyHex)
			}
			fmt.Fprintf(out, "Faults:     usable=%d  ignored=%d  total=%d\n",
				res.UsableFaults, res.IgnoredFaults, res.TotalFaultsInput)
			fmt.Fprintln(out, "\nShiftRows Columns:")
			for _, col := range res.Columns {
				fmt.Fprintf(out, "  col[%d] bytes=%v  solved=%-5v  faults=%d  candidates=%d  subkey=%s\n",
					col.GroupIndex, col.ByteIndices, col.Solved, col.FaultCount, col.CandidateCount, col.SubkeyBytesHex)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&validHex, "valid", "", "valid 16-byte AES-128 ciphertext in hex")
	cmd.Flags().StringSliceVar(&faults, "fault", nil, "faulty 16-byte ciphertext in hex (repeatable or comma-separated)")
	cmd.Flags().StringVar(&faultFile, "fault-file", "", "file containing newline-separated faulty ciphertexts in hex")
	cmd.Flags().StringVar(&plaintextHex, "plaintext", "", "optional 16-byte plaintext in hex to verify recovered key")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output DFAResult JSON")
	_ = cmd.MarkFlagRequired("valid")
	return cmd
}

func newCryptoDFAScriptCmd() *cobra.Command {
	var (
		engine  string
		cfg     cryptolab.DFAScriptConfig
		xorHex  string
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "dfa-script",
		Short: "Generate a Unidbg (Java) or Qiling (Python) Round-9 White-Box AES DFA fault-injection script",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			normEngine := strings.ToLower(strings.TrimSpace(engine))
			switch normEngine {
			case "unidbg", "qiling":
			default:
				return fmt.Errorf("unsupported --engine %q (expected unidbg or qiling)", engine)
			}
			if strings.TrimSpace(xorHex) != "" {
				clean := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(xorHex), "0x"), "0X")
				v, err := strconv.ParseUint(clean, 16, 8)
				if err != nil {
					return fmt.Errorf("invalid --xor byte %q: %w", xorHex, err)
				}
				cfg.FaultXOR = byte(v)
			}

			sc := cryptolab.GenerateDFAFaultScript(normEngine, cfg)
			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(sc.Code), 0o644); err != nil {
					return fmt.Errorf("write DFA script %s: %w", outFile, err)
				}
				fmt.Fprintf(out, "Saved %s DFA fault-injection script (%s) to %s\n", sc.Engine, sc.FileName, outFile)
				return nil
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(sc)
			}
			fmt.Fprint(out, sc.Code)
			if !strings.HasSuffix(sc.Code, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&engine, "engine", "e", "unidbg", "emulation engine: unidbg or qiling")
	cmd.Flags().StringVar(&cfg.BinaryPath, "binary", "", "target native binary / .so path")
	cmd.Flags().StringVar(&cfg.APKPath, "apk", "", "target APK path")
	cmd.Flags().StringVar(&cfg.PackageName, "pkg", "", "Android package name")
	cmd.Flags().StringVar(&cfg.Arch, "arch", "arm64", "target architecture: arm64, arm, x86_64")
	cmd.Flags().StringVar(&cfg.RootFS, "rootfs", "", "Qiling rootfs directory")
	cmd.Flags().StringVar(&cfg.TargetClass, "class", "", "JNI target class path (Unidbg)")
	cmd.Flags().StringVar(&cfg.TargetMethod, "method", "", "JNI target method name (Unidbg)")
	cmd.Flags().StringVar(&cfg.MethodSignature, "sig", "", "JNI method descriptor")
	cmd.Flags().StringVar(&cfg.TargetSymbol, "symbol", "", "exported C symbol name")
	cmd.Flags().StringVar(&cfg.TargetAddr, "addr", "", "target function hex address")
	cmd.Flags().StringVar(&cfg.FaultHookAddr, "hook-addr", "", "Round-9 pre-MixColumns hook hex address")
	cmd.Flags().StringVar(&cfg.StateBufReg, "reg", "", "register holding 16-byte AES state buffer pointer")
	cmd.Flags().StringVar(&cfg.StateBufAddr, "state-addr", "", "fixed hex address of 16-byte AES state buffer")
	cmd.Flags().StringVar(&cfg.PlaintextHex, "plaintext", "", "16-byte input plaintext in hex")
	cmd.Flags().StringVar(&xorHex, "xor", "", "single-byte fault XOR mask in hex (e.g. 0x01)")
	cmd.Flags().IntVar(&cfg.FaultsPerByte, "faults-per-byte", 0, "fault injections per state byte")
	cmd.Flags().StringVar(&cfg.ClassName, "java-class", "", "generated Java harness class name")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write generated script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedDFAScript JSON")
	return cmd
}
