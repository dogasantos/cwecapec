package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// API endpoints
	NVDAPI               = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	EPSSAPI              = "https://api.first.org/data/v1/epss"
	AtomicRedTeamBaseURL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"
)

// Command-line flags
var (
	cveID      string
	outputHTML string
)

// Data structures for local database
type LocalDB struct {
	CWEs          map[string]CWEInfo       `json:"-"`
	CAPECs        map[string]CAPECInfo     `json:"-"`
	Techniques    map[string]TechniqueInfo `json:"-"`
	Groups        map[string]GroupInfo     `json:"-"`
	Software      map[string]SoftwareInfo  `json:"-"`
	Relationships RelationshipsDB          `json:"-"`
}

type CWEInfo struct {
	Name                  string   `json:"name"`
	ChildOf               []string `json:"childOf"`
	RelatedAttackPatterns []string `json:"relatedAttackPatterns"`
}

type CAPECInfo struct {
	Name                  string                     `json:"name"`
	Description           string                     `json:"description,omitempty"`
	LikelihoodOfAttack    string                     `json:"likelihoodOfAttack,omitempty"`
	TypicalSeverity       string                     `json:"typicalSeverity,omitempty"`
	RelatedAttackPatterns []RelatedAttackPatternInfo `json:"relatedAttackPatterns,omitempty"`
	RelatedWeaknesses     []string                   `json:"relatedWeaknesses,omitempty"`
	MitreAttack           []string                   `json:"mitreAttack,omitempty"`
	Prerequisites         []string                   `json:"prerequisites,omitempty"`
}

type RelatedAttackPatternInfo struct {
	Nature  string `json:"nature"`
	CAPECID string `json:"capecId"`
}

type TechniqueInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tactics     []string `json:"tactics,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	Software    []string `json:"software,omitempty"`
	URL         string   `json:"url,omitempty"`
}

type GroupInfo struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases,omitempty"`
	Description string   `json:"description,omitempty"`
	Techniques  []string `json:"techniques,omitempty"`
	URL         string   `json:"url,omitempty"`
}

type SoftwareInfo struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Techniques  []string `json:"techniques,omitempty"`
	URL         string   `json:"url,omitempty"`
}

type RelationshipsDB struct {
	CWEToCapec    map[string][]string `json:"cwe_to_capec"`
	CapecToCWE    map[string][]string `json:"capec_to_cwe"`
	CapecToAttack map[string][]string `json:"capec_to_attack"`
	AttackToCapec map[string][]string `json:"attack_to_capec"`
}

// NVD API response structures
type NVDResponse struct {
	Vulnerabilities []struct {
		CVE CVEItem `json:"cve"`
	} `json:"vulnerabilities"`
}

type CVEItem struct {
	ID           string        `json:"id"`
	Descriptions []Description `json:"descriptions"`
	Weaknesses   []Weakness    `json:"weaknesses"`
	Metrics      Metrics       `json:"metrics"`
	Published    string        `json:"published"`
	LastModified string        `json:"lastModified"`
	References   []Reference   `json:"references"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Weakness struct {
	Description []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"description"`
}

type Metrics struct {
	CvssMetricV31 []CVSSMetric `json:"cvssMetricV31"`
	CvssMetricV30 []CVSSMetric `json:"cvssMetricV30"`
	CvssMetricV2  []CVSSMetric `json:"cvssMetricV2"`
}

type CVSSMetric struct {
	CvssData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// EPSS API response structures
type EPSSResponse struct {
	Data []EPSSData `json:"data"`
}

type EPSSData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// Atomic Red Team YAML structure
type AtomicTest struct {
	AttackTechnique string `yaml:"attack_technique"`
	DisplayName     string `yaml:"display_name"`
	AtomicTests     []struct {
		Name               string   `yaml:"name"`
		Description        string   `yaml:"description"`
		SupportedPlatforms []string `yaml:"supported_platforms"`
		Executor           struct {
			Name    string `yaml:"name"`
			Command string `yaml:"command"`
		} `yaml:"executor"`
	} `yaml:"atomic_tests"`
}

// Report data structure
type Report struct {
	CVE          CVEItem
	CWEs         []CWEDetail
	CAPECs       []CAPECDetail
	Techniques   []TechniqueDetail
	ThreatActors []ThreatActorDetail
	AtomicTests  []AtomicTestDetail
	EPSS         EPSSDetail
	GeneratedAt  time.Time
}

type CWEDetail struct {
	ID          string
	Name        string
	Description string
}

type CAPECDetail struct {
	ID                 string
	Name               string
	Description        string
	LikelihoodOfAttack string
	TypicalSeverity    string
	Prerequisites      []string
}

type TechniqueDetail struct {
	ID          string
	Name        string
	Description string
	Tactics     []string
	Platforms   []string
	URL         string
}

type ThreatActorDetail struct {
	ID          string
	Name        string
	Aliases     []string
	Description string
	Source      string // "CVE" or "Technique"
	URL         string
}

type AtomicTestDetail struct {
	TechniqueID string
	TestName    string
	Description string
	Platform    string
	Command     string
}

type EPSSDetail struct {
	Current    EPSSData
	TimeSeries []EPSSData
}

func main() {
	flag.StringVar(&cveID, "cve", "", "CVE ID to query (e.g., CVE-2024-1234)")
	flag.StringVar(&outputHTML, "html", "", "Output HTML report file (optional)")
	flag.Parse()

	if cveID == "" {
		fmt.Println("Usage: cve-query -cve CVE-YYYY-NNNNN [-html output.html]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load local databases
	fmt.Println("Loading local databases...")
	db, err := loadLocalDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading databases: %v\n", err)
		os.Exit(1)
	}

	// Query CVE from NVD
	fmt.Printf("Querying NVD for %s...\n", cveID)
	cveData, err := queryNVD(cveID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying NVD: %v\n", err)
		os.Exit(1)
	}

	// Query EPSS
	fmt.Printf("Querying EPSS data...\n")
	epssData, err := queryEPSS(cveID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Error querying EPSS: %v\n", err)
		epssData = EPSSDetail{} // Continue without EPSS
	}

	// Build report
	fmt.Println("Building attack chain...")
	report := buildReport(cveData, epssData, db)

	// Output
	if outputHTML != "" {
		fmt.Printf("Generating HTML report: %s\n", outputHTML)
		if err := generateHTMLReport(report, outputHTML); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating HTML: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ HTML report generated successfully")
	}

	// Always output to console
	printConsoleReport(report)
}

func loadLocalDB() (*LocalDB, error) {
	db := &LocalDB{}

	// Load CWE database
	cweData, err := os.ReadFile("resources/cwe_db.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read cwe_db.json: %w", err)
	}
	if err := json.Unmarshal(cweData, &db.CWEs); err != nil {
		return nil, fmt.Errorf("failed to parse cwe_db.json: %w", err)
	}

	// Load CAPEC database
	capecData, err := os.ReadFile("resources/capec_db.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read capec_db.json: %w", err)
	}
	if err := json.Unmarshal(capecData, &db.CAPECs); err != nil {
		return nil, fmt.Errorf("failed to parse capec_db.json: %w", err)
	}

	// Load ATT&CK techniques
	techData, err := os.ReadFile("resources/attack_techniques_db.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read attack_techniques_db.json: %w", err)
	}
	if err := json.Unmarshal(techData, &db.Techniques); err != nil {
		return nil, fmt.Errorf("failed to parse attack_techniques_db.json: %w", err)
	}

	// Load ATT&CK groups
	groupData, err := os.ReadFile("resources/attack_groups_db.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read attack_groups_db.json: %w", err)
	}
	if err := json.Unmarshal(groupData, &db.Groups); err != nil {
		return nil, fmt.Errorf("failed to parse attack_groups_db.json: %w", err)
	}

	// Load ATT&CK software
	softData, err := os.ReadFile("resources/attack_software_db.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read attack_software_db.json: %w", err)
	}
	if err := json.Unmarshal(softData, &db.Software); err != nil {
		return nil, fmt.Errorf("failed to parse attack_software_db.json: %w", err)
	}

	// Load relationships
	relData, err := os.ReadFile("resources/relationships_db.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read relationships_db.json: %w", err)
	}
	if err := json.Unmarshal(relData, &db.Relationships); err != nil {
		return nil, fmt.Errorf("failed to parse relationships_db.json: %w", err)
	}

	return db, nil
}

func queryNVD(cveID string) (CVEItem, error) {
	url := fmt.Sprintf("%s?cveId=%s", NVDAPI, cveID)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return CVEItem{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CVEItem{}, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return CVEItem{}, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return CVEItem{}, fmt.Errorf("CVE not found")
	}

	return nvdResp.Vulnerabilities[0].CVE, nil
}

func queryEPSS(cveID string) (EPSSDetail, error) {
	detail := EPSSDetail{}

	// Query current EPSS score
	url := fmt.Sprintf("%s?cve=%s", EPSSAPI, cveID)
	current, err := fetchEPSS(url)
	if err != nil {
		return detail, err
	}
	if len(current) > 0 {
		detail.Current = current[0]
	}

	// Query time series (last 30 days)
	urlTimeSeries := fmt.Sprintf("%s?cve=%s&scope=time-series", EPSSAPI, cveID)
	timeSeries, err := fetchEPSS(urlTimeSeries)
	if err != nil {
		return detail, err
	}
	detail.TimeSeries = timeSeries

	return detail, nil
}

func fetchEPSS(url string) ([]EPSSData, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var epssResp EPSSResponse
	if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
		return nil, fmt.Errorf("failed to parse EPSS response: %w", err)
	}

	return epssResp.Data, nil
}

func buildReport(cve CVEItem, epss EPSSDetail, db *LocalDB) Report {
	report := Report{
		CVE:         cve,
		EPSS:        epss,
		GeneratedAt: time.Now(),
	}

	// Extract CWE IDs from CVE
	cweIDs := extractCWEIDs(cve)

	// Build CWE details
	for _, cweID := range cweIDs {
		if cweInfo, ok := db.CWEs[cweID]; ok {
			report.CWEs = append(report.CWEs, CWEDetail{
				ID:   cweID,
				Name: cweInfo.Name,
			})
		}
	}

	// Build CAPEC details (from CWE relationships)
	capecSet := make(map[string]bool)
	for _, cweID := range cweIDs {
		if capecIDs, ok := db.Relationships.CWEToCapec[cweID]; ok {
			for _, capecID := range capecIDs {
				capecSet[capecID] = true
			}
		}
	}

	for capecID := range capecSet {
		if capecInfo, ok := db.CAPECs[capecID]; ok {
			report.CAPECs = append(report.CAPECs, CAPECDetail{
				ID:                 capecID,
				Name:               capecInfo.Name,
				Description:        capecInfo.Description,
				LikelihoodOfAttack: capecInfo.LikelihoodOfAttack,
				TypicalSeverity:    capecInfo.TypicalSeverity,
				Prerequisites:      capecInfo.Prerequisites,
			})
		}
	}

	// Build Technique details (from CAPEC relationships)
	techniqueSet := make(map[string]bool)
	for capecID := range capecSet {
		if techIDs, ok := db.Relationships.CapecToAttack[capecID]; ok {
			for _, techID := range techIDs {
				techniqueSet[techID] = true
			}
		}
	}

	for techID := range techniqueSet {
		if techInfo, ok := db.Techniques[techID]; ok {
			report.Techniques = append(report.Techniques, TechniqueDetail{
				ID:          techID,
				Name:        techInfo.Name,
				Description: techInfo.Description,
				Tactics:     techInfo.Tactics,
				Platforms:   techInfo.Platforms,
				URL:         techInfo.URL,
			})
		}
	}

	// Build Threat Actor details
	actorSet := make(map[string]ThreatActorDetail)

	// Actors using these techniques
	for techID := range techniqueSet {
		if techInfo, ok := db.Techniques[techID]; ok {
			for _, groupID := range techInfo.Groups {
				if groupInfo, ok := db.Groups[groupID]; ok {
					if _, exists := actorSet[groupID]; !exists {
						actorSet[groupID] = ThreatActorDetail{
							ID:          groupID,
							Name:        groupInfo.Name,
							Aliases:     groupInfo.Aliases,
							Description: groupInfo.Description,
							Source:      "Technique",
							URL:         groupInfo.URL,
						}
					}
				}
			}
		}
	}

	for _, actor := range actorSet {
		report.ThreatActors = append(report.ThreatActors, actor)
	}

	// Fetch Atomic Red Team tests
	for techID := range techniqueSet {
		tests := fetchAtomicTests(techID)
		report.AtomicTests = append(report.AtomicTests, tests...)
	}

	return report
}

func extractCWEIDs(cve CVEItem) []string {
	cweSet := make(map[string]bool)

	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			// CWE IDs are in format "CWE-123"
			if strings.HasPrefix(desc.Value, "CWE-") {
				cweSet[strings.TrimPrefix(desc.Value, "CWE-")] = true
			}
		}
	}

	cweIDs := make([]string, 0, len(cweSet))
	for id := range cweSet {
		cweIDs = append(cweIDs, id)
	}
	sort.Strings(cweIDs)

	return cweIDs
}

func fetchAtomicTests(techniqueID string) []AtomicTestDetail {
	var tests []AtomicTestDetail

	// Construct URL to YAML file
	url := fmt.Sprintf("%s/%s/%s.yaml", AtomicRedTeamBaseURL, techniqueID, techniqueID)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return tests // Return empty if not found
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return tests
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tests
	}

	var atomic AtomicTest
	if err := yaml.Unmarshal(body, &atomic); err != nil {
		return tests
	}

	for _, test := range atomic.AtomicTests {
		platforms := "N/A"
		if len(test.SupportedPlatforms) > 0 {
			platforms = strings.Join(test.SupportedPlatforms, ", ")
		}

		tests = append(tests, AtomicTestDetail{
			TechniqueID: techniqueID,
			TestName:    test.Name,
			Description: test.Description,
			Platform:    platforms,
			Command:     test.Executor.Command,
		})
	}

	return tests
}

func printConsoleReport(report Report) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("CVE ATTACK CHAIN ANALYSIS: %s\n", report.CVE.ID)
	fmt.Println(strings.Repeat("=", 80))

	// CVE Information
	fmt.Println("\n[CVE INFORMATION]")
	fmt.Printf("ID: %s\n", report.CVE.ID)
	if len(report.CVE.Descriptions) > 0 {
		fmt.Printf("Description: %s\n", report.CVE.Descriptions[0].Value)
	}
	fmt.Printf("Published: %s\n", report.CVE.Published)
	fmt.Printf("Last Modified: %s\n", report.CVE.LastModified)

	// CVSS Scores
	if len(report.CVE.Metrics.CvssMetricV31) > 0 {
		cvss := report.CVE.Metrics.CvssMetricV31[0].CvssData
		fmt.Printf("CVSS v3.1: %.1f (%s) - %s\n", cvss.BaseScore, cvss.BaseSeverity, cvss.VectorString)
	} else if len(report.CVE.Metrics.CvssMetricV30) > 0 {
		cvss := report.CVE.Metrics.CvssMetricV30[0].CvssData
		fmt.Printf("CVSS v3.0: %.1f (%s) - %s\n", cvss.BaseScore, cvss.BaseSeverity, cvss.VectorString)
	} else if len(report.CVE.Metrics.CvssMetricV2) > 0 {
		cvss := report.CVE.Metrics.CvssMetricV2[0].CvssData
		fmt.Printf("CVSS v2: %.1f - %s\n", cvss.BaseScore, cvss.VectorString)
	}

	// EPSS
	if report.EPSS.Current.EPSS != "" {
		fmt.Printf("\n[EPSS - Exploit Prediction]\n")
		fmt.Printf("Current Score: %s (Percentile: %s)\n", report.EPSS.Current.EPSS, report.EPSS.Current.Percentile)
		if len(report.EPSS.TimeSeries) > 0 {
			fmt.Printf("30-Day Trend: %d data points available\n", len(report.EPSS.TimeSeries))
		}
	}

	// CWEs
	if len(report.CWEs) > 0 {
		fmt.Printf("\n[RELATED CWEs] (%d)\n", len(report.CWEs))
		for _, cwe := range report.CWEs {
			fmt.Printf("  • CWE-%s: %s\n", cwe.ID, cwe.Name)
		}
	}

	// CAPECs
	if len(report.CAPECs) > 0 {
		fmt.Printf("\n[RELATED ATTACK PATTERNS (CAPEC)] (%d)\n", len(report.CAPECs))
		for _, capec := range report.CAPECs {
			fmt.Printf("  • CAPEC-%s: %s\n", capec.ID, capec.Name)
			if capec.LikelihoodOfAttack != "" {
				fmt.Printf("    Likelihood: %s | Severity: %s\n", capec.LikelihoodOfAttack, capec.TypicalSeverity)
			}
		}
	}

	// Techniques
	if len(report.Techniques) > 0 {
		fmt.Printf("\n[MITRE ATT&CK TECHNIQUES] (%d)\n", len(report.Techniques))
		for _, tech := range report.Techniques {
			fmt.Printf("  • %s: %s\n", tech.ID, tech.Name)
			if len(tech.Tactics) > 0 {
				fmt.Printf("    Tactics: %s\n", strings.Join(tech.Tactics, ", "))
			}
			if len(tech.Platforms) > 0 {
				fmt.Printf("    Platforms: %s\n", strings.Join(tech.Platforms, ", "))
			}
		}
	}

	// Threat Actors
	if len(report.ThreatActors) > 0 {
		fmt.Printf("\n[THREAT ACTORS / APT GROUPS] (%d)\n", len(report.ThreatActors))
		for _, actor := range report.ThreatActors {
			fmt.Printf("  • %s: %s\n", actor.ID, actor.Name)
			if len(actor.Aliases) > 0 {
				fmt.Printf("    Aliases: %s\n", strings.Join(actor.Aliases, ", "))
			}
		}
	}

	// Atomic Red Team Tests
	if len(report.AtomicTests) > 0 {
		fmt.Printf("\n[ATOMIC RED TEAM TESTS] (%d)\n", len(report.AtomicTests))
		for i, test := range report.AtomicTests {
			if i >= 10 {
				fmt.Printf("  ... and %d more tests (see HTML report for full list)\n", len(report.AtomicTests)-10)
				break
			}
			fmt.Printf("  • [%s] %s\n", test.TechniqueID, test.TestName)
			fmt.Printf("    Platform: %s\n", test.Platform)
			if test.Command != "" {
				cmdPreview := test.Command
				if len(cmdPreview) > 100 {
					cmdPreview = cmdPreview[:100] + "..."
				}
				fmt.Printf("    Command: %s\n", cmdPreview)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("Report generated at: %s\n", report.GeneratedAt.Format(time.RFC1123))
	fmt.Println(strings.Repeat("=", 80))
}

func generateHTMLReport(report Report, filename string) error {
	html := buildHTMLReport(report)
	return os.WriteFile(filename, []byte(html), 0644)
}

func buildHTMLReport(report Report) string {
	// Build EPSS chart data
	epssChartData := ""
	if len(report.EPSS.TimeSeries) > 0 {
		epssChartData = buildEPSSChartData(report.EPSS.TimeSeries)
	}

	cvssScore := "N/A"
	cvssSeverity := "N/A"
	cvssVector := ""
	if len(report.CVE.Metrics.CvssMetricV31) > 0 {
		cvss := report.CVE.Metrics.CvssMetricV31[0].CvssData
		cvssScore = fmt.Sprintf("%.1f", cvss.BaseScore)
		cvssSeverity = cvss.BaseSeverity
		cvssVector = cvss.VectorString
	}

	epssScore := "N/A"
	epssPercentile := "N/A"
	if report.EPSS.Current.EPSS != "" {
		epssScore = report.EPSS.Current.EPSS
		epssPercentile = report.EPSS.Current.Percentile
	}

	description := "No description available"
	if len(report.CVE.Descriptions) > 0 {
		description = report.CVE.Descriptions[0].Value
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE Analysis Report: %s</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%%, #2a5298 100%%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
            padding: 30px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .section h2 {
            color: #1e3c72;
            margin-bottom: 20px;
            font-size: 1.8em;
            display: flex;
            align-items: center;
        }
        
        .section h2::before {
            content: '';
            display: inline-block;
            width: 8px;
            height: 30px;
            background: #667eea;
            margin-right: 15px;
            border-radius: 4px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .metric-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-top: 3px solid #667eea;
        }
        
        .metric-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .metric-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #1e3c72;
        }
        
        .metric-card .label {
            font-size: 0.9em;
            color: #999;
            margin-top: 5px;
        }
        
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        
        .item-list {
            list-style: none;
        }
        
        .item-list li {
            padding: 15px;
            margin: 10px 0;
            background: white;
            border-radius: 6px;
            border-left: 3px solid #667eea;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .item-list li strong {
            color: #1e3c72;
            font-size: 1.1em;
        }
        
        .item-list li .details {
            margin-top: 8px;
            color: #666;
            font-size: 0.95em;
        }
        
        .item-list li .tags {
            margin-top: 8px;
        }
        
        .tag {
            display: inline-block;
            padding: 4px 12px;
            margin: 4px 4px 4px 0;
            background: #e7f3ff;
            color: #0066cc;
            border-radius: 12px;
            font-size: 0.85em;
        }
        
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-top: 10px;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #dee2e6;
        }
        
        a {
            color: #667eea;
            text-decoration: none;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        .badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .badge-count {
            background: #667eea;
            color: white;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 CVE Attack Chain Analysis</h1>
            <div class="subtitle">%s</div>
            <div class="subtitle" style="margin-top: 10px; font-size: 0.9em;">Generated: %s</div>
        </div>
        
        <div class="content">
            <!-- CVE Overview -->
            <div class="section">
                <h2>CVE Overview</h2>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <h3>CVE ID</h3>
                        <div class="value">%s</div>
                    </div>
                    <div class="metric-card">
                        <h3>CVSS Score</h3>
                        <div class="value severity-%s">%s</div>
                        <div class="label">%s</div>
                    </div>
                    <div class="metric-card">
                        <h3>EPSS Score</h3>
                        <div class="value">%s</div>
                        <div class="label">Percentile: %s</div>
                    </div>
                    <div class="metric-card">
                        <h3>Published</h3>
                        <div class="value" style="font-size: 1.3em;">%s</div>
                    </div>
                </div>
                <p style="margin-top: 20px; line-height: 1.8;"><strong>Description:</strong> %s</p>
                %s
            </div>`,
		report.CVE.ID,
		report.CVE.ID,
		report.GeneratedAt.Format("2006-01-02 15:04:05 MST"),
		report.CVE.ID,
		strings.ToLower(cvssSeverity),
		cvssScore,
		cvssSeverity,
		epssScore,
		epssPercentile,
		formatDate(report.CVE.Published),
		description,
		cvssVector,
	)

	// EPSS Chart
	if epssChartData != "" {
		html += fmt.Sprintf(`
            <!-- EPSS Trend -->
            <div class="section">
                <h2>EPSS Trend (Last 30 Days)</h2>
                <div class="chart-container">
                    <canvas id="epssChart"></canvas>
                </div>
            </div>
            <script>
                %s
            </script>`, epssChartData)
	}

	// CWEs
	if len(report.CWEs) > 0 {
		html += fmt.Sprintf(`
            <div class="section">
                <h2>Related Weaknesses (CWE)<span class="badge badge-count">%d</span></h2>
                <ul class="item-list">`, len(report.CWEs))
		for _, cwe := range report.CWEs {
			html += fmt.Sprintf(`
                    <li>
                        <strong>CWE-%s</strong>: %s
                    </li>`, cwe.ID, cwe.Name)
		}
		html += `
                </ul>
            </div>`
	}

	// CAPECs
	if len(report.CAPECs) > 0 {
		html += fmt.Sprintf(`
            <div class="section">
                <h2>Attack Patterns (CAPEC)<span class="badge badge-count">%d</span></h2>
                <ul class="item-list">`, len(report.CAPECs))
		for _, capec := range report.CAPECs {
			html += fmt.Sprintf(`
                    <li>
                        <strong>CAPEC-%s</strong>: %s
                        <div class="details">%s</div>`, capec.ID, capec.Name, capec.Description)
			if capec.LikelihoodOfAttack != "" || capec.TypicalSeverity != "" {
				html += fmt.Sprintf(`
                        <div class="tags">
                            <span class="tag">Likelihood: %s</span>
                            <span class="tag">Severity: %s</span>
                        </div>`, capec.LikelihoodOfAttack, capec.TypicalSeverity)
			}
			html += `
                    </li>`
		}
		html += `
                </ul>
            </div>`
	}

	// Techniques
	if len(report.Techniques) > 0 {
		html += fmt.Sprintf(`
            <div class="section">
                <h2>MITRE ATT&CK Techniques<span class="badge badge-count">%d</span></h2>
                <ul class="item-list">`, len(report.Techniques))
		for _, tech := range report.Techniques {
			html += fmt.Sprintf(`
                    <li>
                        <strong><a href="%s" target="_blank">%s</a></strong>: %s
                        <div class="details">%s</div>`, tech.URL, tech.ID, tech.Name, tech.Description)
			if len(tech.Tactics) > 0 || len(tech.Platforms) > 0 {
				html += `<div class="tags">`
				for _, tactic := range tech.Tactics {
					html += fmt.Sprintf(`<span class="tag">%s</span>`, tactic)
				}
				for _, platform := range tech.Platforms {
					html += fmt.Sprintf(`<span class="tag">%s</span>`, platform)
				}
				html += `</div>`
			}
			html += `
                    </li>`
		}
		html += `
                </ul>
            </div>`
	}

	// Threat Actors
	if len(report.ThreatActors) > 0 {
		html += fmt.Sprintf(`
            <div class="section">
                <h2>Threat Actors / APT Groups<span class="badge badge-count">%d</span></h2>
                <ul class="item-list">`, len(report.ThreatActors))
		for _, actor := range report.ThreatActors {
			html += fmt.Sprintf(`
                    <li>
                        <strong><a href="%s" target="_blank">%s</a></strong>: %s`, actor.URL, actor.ID, actor.Name)
			if len(actor.Aliases) > 0 {
				html += fmt.Sprintf(`
                        <div class="details">Aliases: %s</div>`, strings.Join(actor.Aliases, ", "))
			}
			if actor.Description != "" {
				html += fmt.Sprintf(`
                        <div class="details">%s</div>`, actor.Description)
			}
			html += `
                    </li>`
		}
		html += `
                </ul>
            </div>`
	}

	// Atomic Tests
	if len(report.AtomicTests) > 0 {
		html += fmt.Sprintf(`
            <div class="section">
                <h2>Atomic Red Team Tests<span class="badge badge-count">%d</span></h2>
                <ul class="item-list">`, len(report.AtomicTests))
		for _, test := range report.AtomicTests {
			html += fmt.Sprintf(`
                    <li>
                        <strong>[%s]</strong> %s
                        <div class="details">%s</div>
                        <div class="tags"><span class="tag">%s</span></div>`,
				test.TechniqueID, test.TestName, test.Description, test.Platform)
			if test.Command != "" {
				html += fmt.Sprintf(`
                        <div class="code-block">%s</div>`, escapeHTML(test.Command))
			}
			html += `
                    </li>`
		}
		html += `
                </ul>
            </div>`
	}

	html += fmt.Sprintf(`
        </div>
        
        <div class="footer">
            <p>Report generated by CVE Query Tool | %s</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Data sources: NVD, EPSS, MITRE ATT&CK, Atomic Red Team</p>
        </div>
    </div>
</body>
</html>`, report.GeneratedAt.Format("2006-01-02 15:04:05 MST"))

	return html
}

func buildEPSSChartData(timeSeries []EPSSData) string {
	if len(timeSeries) == 0 {
		return ""
	}

	// Sort by date
	sort.Slice(timeSeries, func(i, j int) bool {
		return timeSeries[i].Date < timeSeries[j].Date
	})

	labels := make([]string, len(timeSeries))
	data := make([]string, len(timeSeries))

	for i, point := range timeSeries {
		labels[i] = fmt.Sprintf("'%s'", point.Date)
		data[i] = point.EPSS
	}

	return fmt.Sprintf(`
        const ctx = document.getElementById('epssChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: [%s],
                datasets: [{
                    label: 'EPSS Score',
                    data: [%s],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    title: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 1,
                        title: {
                            display: true,
                            text: 'EPSS Score (Probability)'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Date'
                        }
                    }
                }
            }
        });`,
		strings.Join(labels, ", "),
		strings.Join(data, ", "))
}

func formatDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr
	}
	return t.Format("2006-01-02")
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
