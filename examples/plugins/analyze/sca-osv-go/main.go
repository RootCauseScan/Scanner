package main

// Analyze plugin that inspects dependency files and queries OSV.dev for
// known vulnerabilities.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// request represents a JSON-RPC request.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// errorObj follows the JSON-RPC error format.
type errorObj struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// fileSpec describes a file sent to the plugin.
type fileSpec struct {
	Path       string  `json:"path"`
	ContentB64 *string `json:"content_b64,omitempty"`
}

type fileAnalyzeParams struct {
	Files []fileSpec `json:"files"`
}

// dependency holds package metadata for OSV queries.
type dependency struct {
	Name      string
	Version   string
	Ecosystem string
}

type depHit struct {
	Dep     dependency
	Line    int
	Excerpt string
}

// In-memory OSV query cache per (ecosystem|name|version)
var vulnCache = map[string][]string{}

func cacheKey(dep dependency) string {
	return dep.Ecosystem + "|" + dep.Name + "|" + dep.Version
}

func queryOSVCached(dep dependency) ([]string, error) {
	if v, ok := vulnCache[cacheKey(dep)]; ok {
		return v, nil
	}
	ids, err := queryOSV(dep)
	if err == nil {
		vulnCache[cacheKey(dep)] = ids
	}
	return ids, err
}

// parsePackageJSON extracts dependencies from a package.json (dependencies + devDependencies)
func parsePackageJSON(data []byte) []depHit {
	type pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	var p pkg
	if err := json.Unmarshal(data, &p); err != nil {
		return nil
	}
	var hits []depHit
	add := func(name, ver string) {
		ver = strings.TrimSpace(ver)
		ver = strings.TrimPrefix(ver, "^")
		ver = strings.TrimPrefix(ver, ">=")
		ver = strings.TrimPrefix(ver, "~")
		hits = append(hits, depHit{Dep: dependency{Name: name, Version: ver, Ecosystem: "npm"}, Line: 1, Excerpt: name + ": " + ver})
	}
	for k, v := range p.Dependencies {
		add(k, v)
	}
	for k, v := range p.DevDependencies {
		add(k, v)
	}
	return hits
}

// osvResponse mirrors the subset of OSV response we need.
type osvResponse struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

// findingOut matches the Rust engine Finding schema (subset used).
type findingOut struct {
	Id         string  `json:"id"`
	RuleId     string  `json:"rule_id"`
	Severity   string  `json:"severity"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Column     int     `json:"column"`
	Excerpt    string  `json:"excerpt"`
	Message    string  `json:"message"`
	Remediation *string `json:"remediation,omitempty"`
	Fix        *string `json:"fix,omitempty"`
}

func send(id interface{}, result interface{}, err *errorObj) {
	resp := map[string]interface{}{"jsonrpc": "2.0", "id": id}
	if err != nil {
		resp["error"] = err
	} else {
		resp["result"] = result
	}
	b, _ := json.Marshal(resp)
	fmt.Println(string(b))
}

// readFile loads data from base64 content or the filesystem.
func readFile(f fileSpec) ([]byte, error) {
	switch {
	case f.ContentB64 != nil && *f.ContentB64 != "":
		return base64.StdEncoding.DecodeString(*f.ContentB64)
	case f.Path != "":
		return os.ReadFile(f.Path)
	}
	return nil, fmt.Errorf("no data")
}

func parseRequirements(data []byte) []depHit {
	var hits []depHit
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "==")
		if len(parts) == 2 {
			hits = append(hits, depHit{
				Dep:     dependency{Name: parts[0], Version: parts[1], Ecosystem: "PyPI"},
				Line:    lineNum,
				Excerpt: line,
			})
		}
	}
	return hits
}

func parseGoMod(data []byte) []depHit {
	var hits []depHit
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inBlock := false
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "require ("):
			inBlock = true
			continue
		case line == ")":
			inBlock = false
			continue
		}

		orig := line
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
		} else if !inBlock {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			hits = append(hits, depHit{
				Dep:     dependency{Name: fields[0], Version: fields[1], Ecosystem: "Go"},
				Line:    lineNum,
				Excerpt: orig,
			})
		}
	}
	return hits
	
}

func severityFromID(id string) string {
	if strings.HasPrefix(id, "CVE-") || strings.HasPrefix(id, "GHSA-") {
		return "HIGH"
	}
	if strings.HasPrefix(id, "PYSEC-") {
		return "MEDIUM"
	}
	return "INFO"
}

func ruleForEco(eco string) string {
	switch eco {
	case "PyPI":
		return "osv.pypi"
	case "Go":
		return "osv.go"
	case "npm":
		return "osv.npm"
	case "crates.io":
		return "osv.crates"
	case "Packagist":
		return "osv.packagist"
	case "RubyGems":
		return "osv.rubygems"
	case "Maven":
		return "osv.maven"
	default:
		return "osv.generic"
	}
}

func queryOSV(dep dependency) ([]string, error) {
	payload := map[string]interface{}{
		"package": map[string]string{
			"name":      dep.Name,
			"ecosystem": dep.Ecosystem,
		},
		"version": dep.Version,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", "https://api.osv.dev/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	var ids []string
	for _, v := range res.Vulns {
		ids = append(ids, v.ID)
	}
	return ids, nil
}

// parsePackageLockJSON extracts dependencies from package-lock.json
func parsePackageLockJSON(data []byte) []depHit {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var hits []depHit
	// dependencies map style
	if deps, ok := raw["dependencies"].(map[string]any); ok {
		for name, v := range deps {
			if obj, ok := v.(map[string]any); ok {
				if ver, ok := obj["version"].(string); ok {
					hits = append(hits, depHit{Dep: dependency{Name: name, Version: ver, Ecosystem: "npm"}, Line: 1, Excerpt: name + ": " + ver})
				}
			}
		}
	}
	// packages map style (npm v7+)
	if pkgs, ok := raw["packages"].(map[string]any); ok {
		for path, v := range pkgs {
			if !strings.HasPrefix(path, "node_modules/") {
				continue
			}
			name := strings.TrimPrefix(path, "node_modules/")
			if obj, ok := v.(map[string]any); ok {
				if ver, ok := obj["version"].(string); ok {
					hits = append(hits, depHit{Dep: dependency{Name: name, Version: ver, Ecosystem: "npm"}, Line: 1, Excerpt: name + ": " + ver})
				}
			}
		}
	}
	return hits
}

// parseCargoLock reads Cargo.lock TOML-like format
func parseCargoLock(data []byte) []depHit {
	var hits []depHit
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inPkg := false
	name := ""
	ver := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			inPkg = true
			name = ""
			ver = ""
			continue
		}
		if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[package]]") {
			inPkg = false
		}
		if !inPkg {
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(line[7:], "\" ")
		} else if strings.HasPrefix(line, "version = ") {
			ver = strings.Trim(line[10:], "\" ")
		}
		if name != "" && ver != "" {
			hits = append(hits, depHit{Dep: dependency{Name: name, Version: ver, Ecosystem: "crates.io"}, Line: 1, Excerpt: name + " = " + ver})
			name = ""
			ver = ""
		}
	}
	return hits
}

// parseComposerLock reads composer.lock JSON
func parseComposerLock(data []byte) []depHit {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var hits []depHit
	if pkgs, ok := raw["packages"].([]any); ok {
		for _, it := range pkgs {
			if obj, ok := it.(map[string]any); ok {
				name, _ := obj["name"].(string)
				ver, _ := obj["version"].(string)
				if name != "" && ver != "" {
					ver = strings.TrimPrefix(ver, "v")
					hits = append(hits, depHit{Dep: dependency{Name: name, Version: ver, Ecosystem: "Packagist"}, Line: 1, Excerpt: name + ": " + ver})
				}
			}
		}
	}
	return hits
}

// parseGemfileLock reads Gemfile.lock
func parseGemfileLock(data []byte) []depHit {
	var hits []depHit
	re := regexp.MustCompile(`^\s{2}([A-Za-z0-9_\-]+) \(([^)]+)\)`) //   name (x.y.z)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		m := re.FindStringSubmatch(line)
		if len(m) == 3 {
			name := m[1]
			ver := m[2]
			hits = append(hits, depHit{Dep: dependency{Name: name, Version: ver, Ecosystem: "RubyGems"}, Line: 1, Excerpt: strings.TrimSpace(line)})
		}
	}
	return hits
}

// parsePomXML rudimentary parsing of pom.xml dependencies
func parsePomXML(data []byte) []depHit {
	var hits []depHit
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inDep := false
	group := ""
	artifact := ""
	version := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "<dependency>") {
			inDep = true
			group = ""
			artifact = ""
			version = ""
			continue
		}
		if strings.HasPrefix(line, "</dependency>") {
			if group != "" && artifact != "" && version != "" {
				name := group + ":" + artifact
				hits = append(hits, depHit{Dep: dependency{Name: name, Version: version, Ecosystem: "Maven"}, Line: 1, Excerpt: name + ":" + version})
			}
			inDep = false
			continue
		}
		if !inDep {
			continue
		}
		if strings.Contains(line, "<groupId>") {
			group = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, "<groupId>"), "</groupId>"), " ")
		}
		if strings.Contains(line, "<artifactId>") {
			artifact = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, "<artifactId>"), "</artifactId>"), " ")
		}
		if strings.Contains(line, "<version>") {
			version = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, "<version>"), "</version>"), " ")
		}
	}
	return hits
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		switch req.Method {
		case "plugin.init":
			send(req.ID, map[string]interface{}{
				"ok":             true,
				"capabilities":   []string{"analyze"},
				"plugin_version": "0.1.0",
			}, nil)
		case "file.analyze":
			var params fileAnalyzeParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				send(req.ID, nil, &errorObj{Code: 1001, Message: "invalid params"})
				continue
			}

			var findings []findingOut
			for _, f := range params.Files {
				// Match by exact basename only, as requested
				name := filepath.Base(f.Path)

				data, err := readFile(f)
				if err != nil {
					continue
				}

				var hits []depHit
				switch name {
				case "requirements.txt":
					hits = parseRequirements(data)
				case "go.mod":
					hits = parseGoMod(data)
				case "package.json":
					hits = parsePackageJSON(data)
				case "package-lock.json":
					hits = parsePackageLockJSON(data)
				case "Cargo.lock":
					hits = parseCargoLock(data)
				case "composer.lock":
					hits = parseComposerLock(data)
				case "Gemfile.lock":
					hits = parseGemfileLock(data)
				case "pom.xml":
					hits = parsePomXML(data)
				default:
					continue
				}

				for _, hit := range hits {
					ids, err := queryOSVCached(hit.Dep)
					if err != nil {
						// Log and continue
						fmt.Fprintf(os.Stderr, "Error querying OSV for %s: %v\n", hit.Dep.Name, err)
						continue
					}
					for _, id := range ids {
						sev := severityFromID(id)
						rule := ruleForEco(hit.Dep.Ecosystem)
						msg := fmt.Sprintf("%s %s vulnerable: %s", hit.Dep.Name, hit.Dep.Version, id)
						rem := "Update to a secure version (check OSV)"
						findings = append(findings, findingOut{
							Id:        id,
							RuleId:    rule,
							Severity:  sev,
							File:      f.Path,
							Line:      hit.Line,
							Column:    1,
							Excerpt:   hit.Excerpt,
							Message:   msg,
							Remediation: &rem,
						})
					}
				}
			}
			send(req.ID, findings, nil)
		case "plugin.ping":
			send(req.ID, "pong", nil)
		case "plugin.shutdown":
			send(req.ID, map[string]bool{"ok": true}, nil)
			return
		default:
			send(req.ID, nil, &errorObj{Code: 1002, Message: "unknown method", Data: map[string]string{"method": req.Method}})
		}
	}
}
