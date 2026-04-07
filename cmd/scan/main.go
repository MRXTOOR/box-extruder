package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/api"
	"github.com/box-extruder/dast/internal/cliutil"
	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/exitcode"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/review"
	"github.com/box-extruder/dast/internal/runner"
	"github.com/box-extruder/dast/internal/storage"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		runCmd()
	case "serve":
		serveCmd()
	case "logs":
		logsCmd()
	case "review":
		reviewCmd()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	me := os.Args[0]
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  %s run [-f scan-as-code.yaml] [-work dir] [-skip-zap] [-skip-nuclei] [-skip-katana] [-demo|-v]\n", me)
	fmt.Fprintf(os.Stderr, "  %s logs <jobId|last> [-work dir] [-f] [-poll 300ms]\n", me)
	fmt.Fprintf(os.Stderr, "  %s review <jobId> <findingId> -confirm|-reject|-reopen [-note text] [-actor name] [-work dir]\n", me)
	fmt.Fprintf(os.Stderr, "  %s serve -addr :8080 [-work dir]\n", me)
}

func runCmd() {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("f", "", "path to scan-as-code.yaml")
	workDir := fs.String("work", "work", "workspace root (work/jobs/...)")
	skipZap := fs.Bool("skip-zap", false, "skip ZAP docker baseline step")
	skipNuclei := fs.Bool("skip-nuclei", false, "skip nucleiEngine: cli step (official nuclei binary)")
	skipKatana := fs.Bool("skip-katana", false, "skip katana step (official katana binary)")
	demo := fs.Bool("demo", false, "stderr progress + banner (demo mode)")
	verbose := fs.Bool("v", false, "same as -demo")
	_ = fs.Parse(os.Args[2:])
	var data []byte
	var cfg *config.ScanAsCode
	var err error
	cfgDir := "."
	if *cfgPath == "" {
		cfg, err = buildInteractiveRunConfig()
		if err != nil {
			log.Fatal(err)
		}
		data, err = yaml.Marshal(cfg)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		data, err = os.ReadFile(*cfgPath)
		if err != nil {
			log.Fatal(err)
		}
		cfg, err = config.ParseScanAsCode(data)
		if err != nil {
			log.Fatal(err)
		}
		cfgDir = filepath.Dir(*cfgPath)
	}
	if err := injectInteractiveAuthInputs(cfg); err != nil {
		log.Fatal(err)
	}
	opts := runner.Options{
		WorkDir:        *workDir,
		ConfigYAML:     data,
		Config:         cfg,
		SkipZAPDocker:  *skipZap,
		SkipNucleiCLI:  *skipNuclei,
		SkipKatanaCLI:  *skipKatana,
		ConfigFileDir:  cfgDir,
	}
	if *demo || *verbose {
		opts.OnProgress = cliutil.DemoProgressSink(os.Stderr)
	}
	jobID, err := runner.Run(opts)
	if err != nil {
		log.Println("run error:", err)
	}
	if *demo || *verbose {
		cliutil.PrintDemoBanner(os.Stderr, *workDir, jobID)
	}
	finalPath := filepath.Join(storage.JobRoot(*workDir, jobID), "findings", "findings-final.json")
	code := readExitCode(finalPath)
	log.Println("jobId:", jobID)
	log.Println("artifacts:", storage.JobRoot(*workDir, jobID))
	os.Exit(code)
}

func buildInteractiveRunConfig() (*config.ScanAsCode, error) {
	in := bufio.NewReader(os.Stdin)
	fmt.Fprintln(os.Stderr, "Interactive mode: setup target and auth")
	baseURL, err := promptLine(in, "Target URL (e.g. https://site.example)", true)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	loginURL, err := promptLine(in, "Login endpoint URL", true)
	if err != nil {
		return nil, err
	}
	verifyURL, err := promptLine(in, "Verify endpoint URL (/me, /userinfo)", true)
	if err != nil {
		return nil, err
	}
	contentType, err := promptLine(in, "Login content type [application/json|application/x-www-form-urlencoded] (default application/json)", false)
	if err != nil {
		return nil, err
	}
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		contentType = "application/json"
	}
	userField, err := promptLine(in, "Username/email field name in login body (e.g. email, username, login)", true)
	if err != nil {
		return nil, err
	}
	passField, err := promptLine(in, "Password field name in login body (default password)", false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(passField) == "" {
		passField = "password"
	}
	tokenPath, err := promptLine(in, "Token JSON path (default access_token)", false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(tokenPath) == "" {
		tokenPath = "access_token"
	}
	useCookiesRaw, err := promptLine(in, "Use cookie session fallback? [y/N]", false)
	if err != nil {
		return nil, err
	}
	useCookies := strings.EqualFold(strings.TrimSpace(useCookiesRaw), "y") || strings.EqualFold(strings.TrimSpace(useCookiesRaw), "yes")

	cfg := config.DefaultScanAsCode()
	cfg.Job.Name = "interactive-scan"
	cfg.Targets = []config.Target{{Type: "web", BaseURL: strings.TrimSpace(baseURL), StartPoints: []string{strings.TrimSpace(baseURL)}}}
	cfg.Scope.Allow = []string{"^" + regexpQuoteURLPrefix(strings.TrimSpace(baseURL)) + ".*"}
	cfg.Scope.Deny = nil
	cfg.Auth = &config.Auth{
		Strategy: "providerChain",
		Providers: []config.AuthProvider{{
			Type: "genericLogin",
			ID:   "interactive-login",
			SecretsRef: map[string]string{
				"username": "",
				"password": "",
			},
			InteractiveInputs: []config.AuthInteractiveInput{
				{Name: "username", Prompt: "Username / Email", Required: true},
				{Name: "password", Prompt: "Password", Sensitive: true, Required: true},
			},
			GenericLogin: &config.GenericLoginConfig{
				LoginURL:           strings.TrimSpace(loginURL),
				LoginMethod:        "POST",
				ContentType:        contentType,
				CredentialFields:   map[string]string{"username": strings.TrimSpace(userField), "password": strings.TrimSpace(passField)},
				TokenPath:          strings.TrimSpace(tokenPath),
				TokenType:          "Bearer",
				TokenHeaderName:    "Authorization",
				VerifyURL:          strings.TrimSpace(verifyURL),
				VerifyMethod:       "GET",
				VerifyExpectedStatus: 200,
				UseCookies:         useCookies,
			},
		}},
	}
	cfg.Scan.Plan = []config.ScanStep{
		{StepType: "katana", Enabled: true},
		{StepType: "zapBaseline", Enabled: true, ZAPAutomationFramework: true, ZAPSpiderTraditional: true},
		{StepType: "nucleiTemplates", Enabled: true, TemplatePaths: []string{"templates/example-banner.yaml"}},
	}
	return &cfg, nil
}

func promptLine(in *bufio.Reader, prompt string, required bool) (string, error) {
	for {
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		s, err := in.ReadString('\n')
		if err != nil {
			return "", err
		}
		s = strings.TrimSpace(s)
		if s == "" && required {
			fmt.Fprintln(os.Stderr, "Value is required.")
			continue
		}
		return s, nil
	}
}

func regexpQuoteURLPrefix(baseURL string) string {
	s := strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	repl := strings.NewReplacer(".", "\\.", "?", "\\?", "+", "\\+", "(", "\\(", ")", "\\)", "[", "\\[", "]", "\\]", "{", "\\{", "}", "\\}", "|", "\\|")
	return repl.Replace(s) + "/"
}

func injectInteractiveAuthInputs(cfg *config.ScanAsCode) error {
	if cfg == nil || cfg.Auth == nil || len(cfg.Auth.Providers) == 0 {
		return nil
	}
	in := bufio.NewReader(os.Stdin)
	for i := range cfg.Auth.Providers {
		p := &cfg.Auth.Providers[i]
		if p.Type != "genericLogin" {
			continue
		}
		if p.SecretsRef == nil {
			p.SecretsRef = map[string]string{}
		}
		fields := p.InteractiveInputs
		if len(fields) == 0 {
			fields = []config.AuthInteractiveInput{
				{Name: "email", Prompt: "Email", Required: false},
				{Name: "login", Prompt: "Login", Required: false},
				{Name: "username", Prompt: "Username", Required: false},
				{Name: "password", Prompt: "Password", Sensitive: true, Required: true},
			}
		}
		for _, f := range fields {
			key := strings.TrimSpace(f.Name)
			if key == "" {
				continue
			}
			if existing, ok := p.SecretsRef[key]; ok && strings.TrimSpace(existing) != "" {
				if v, err := config.ResolveSecretRef(existing); err == nil && strings.TrimSpace(v) != "" {
					continue
				}
			}
			prompt := strings.TrimSpace(f.Prompt)
			if prompt == "" {
				prompt = "Input " + key
			}
			required := f.Required
			sensitive := f.Sensitive || strings.Contains(strings.ToLower(key), "pass")
			for {
				var val string
				var err error
				if sensitive {
					val, err = readSecret(prompt)
				} else {
					fmt.Fprintf(os.Stderr, "%s: ", prompt)
					val, err = in.ReadString('\n')
					if err == nil {
						val = strings.TrimSpace(val)
					}
				}
				if err != nil {
					return err
				}
				if strings.TrimSpace(val) == "" && required {
					fmt.Fprintln(os.Stderr, "Value is required.")
					continue
				}
				if strings.TrimSpace(val) != "" {
					p.SecretsRef[key] = strings.TrimSpace(val)
				}
				break
			}
		}
	}
	return nil
}

func readSecret(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func reviewCmd() {
	fs := flag.NewFlagSet("review", flag.ExitOnError)
	workDir := fs.String("work", "work", "workspace root")
	note := fs.String("note", "", "comment for audit trail")
	actor := fs.String("actor", "", "reviewer id (default: $USER)")
	confirm := fs.Bool("confirm", false, "confirm finding")
	reject := fs.Bool("reject", false, "reject as false positive")
	reopen := fs.Bool("reopen", false, "reopen finding")
	_ = fs.Parse(os.Args[2:])
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: scan review <jobId> <findingId> -confirm|-reject|-reopen ...")
		os.Exit(2)
	}
	jobID := fs.Arg(0)
	findingID := fs.Arg(1)
	var n int
	var act review.Action
	if *confirm {
		n++
		act = review.ActionConfirm
	}
	if *reject {
		n++
		act = review.ActionReject
	}
	if *reopen {
		n++
		act = review.ActionReopen
	}
	if n != 1 {
		fmt.Fprintln(os.Stderr, "exactly one of -confirm -reject -reopen is required")
		os.Exit(2)
	}
	if err := review.Apply(*workDir, jobID, findingID, act, *note, *actor); err != nil {
		log.Fatal(err)
	}
	log.Println("review applied:", jobID, findingID, act)
}

func logsCmd() {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	workDir := fs.String("work", "work", "workspace root")
	follow := fs.Bool("f", false, "follow orchestrator.log (poll)")
	pollMs := fs.Int("poll", 300, "follow poll interval (ms)")
	_ = fs.Parse(os.Args[2:])
	spec := fs.Arg(0)
	if spec == "" {
		fmt.Fprintln(os.Stderr, "usage: scan logs <jobId|last> [-work dir] [-f]")
		os.Exit(2)
	}
	id, err := cliutil.ResolveJobID(*workDir, spec)
	if err != nil {
		log.Fatal(err)
	}
	poll := time.Duration(*pollMs) * time.Millisecond
	if err := cliutil.PrintOrchestratorLog(os.Stdout, *workDir, id, *follow, poll); err != nil {
		log.Fatal(err)
	}
}

func readExitCode(finalPath string) int {
	data, err := os.ReadFile(finalPath)
	if err != nil {
		return 0
	}
	var findings []model.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return 0
	}
	return exitcode.FromFindings(findings)
}

func serveCmd() {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	workDir := fs.String("work", "work", "workspace root")
	_ = fs.Parse(os.Args[2:])
	if err := os.MkdirAll(*workDir, 0o755); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	api.NewServer(*workDir).Mount(mux)
	webDir := filepath.Join(".", "web")
	if st, err := os.Stat(webDir); err == nil && st.IsDir() {
		mux.Handle("/", http.FileServer(http.Dir(webDir)))
	}
	log.Println("listening on", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
