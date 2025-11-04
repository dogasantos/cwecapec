package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
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
	maxCAPECs  int
)

// ML models (loaded at startup)
var (
	cweHierarchy *CWEHierarchy
	nbModel      *AttackVectorModel
	taxonomy     *AttackVectorTaxonomy
	capecData    map[string]CAPECTrainingData
	mlEnabled    bool
)

// CAPEC training data for ranking
type CAPECTrainingData struct {
	CAPECID            string   `json:"capec_id"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	LikelihoodOfAttack string   `json:"likelihood_of_attack"`
	TypicalSeverity    string   `json:"typical_severity"`
	RelatedCWEs        []string `json:"related_cwes"`
	Prerequisites      []string `json:"prerequisites"`
}

// CWE to attack vector mapping (highest confidence)
var cweToVector = map[string][]string{
	// Injection vulnerabilities
	"89":  {"sql_injection"},
	"78":  {"command_injection"},
	"77":  {"command_injection"},
	"917": {"code_injection", "jndi_injection"},
	"90":  {"ldap_injection"},
	"643": {"xpath_injection"},
	"652": {"xml_injection"},
	// XSS
	"79": {"xss"},
	"80": {"xss"},
	// Deserialization
	"502": {"deserialization"},
	// Path Traversal
	"22": {"path_traversal"},
	"23": {"path_traversal"},
	// Buffer Overflow
	"119": {"buffer_overflow"},
	"120": {"buffer_overflow"},
	"121": {"buffer_overflow"},
	"122": {"buffer_overflow"},
	"787": {"buffer_overflow"},
	// Authentication
	"287": {"authentication"},
	"288": {"authentication"},
	"290": {"authentication"},
	"306": {"authentication"},
	"798": {"authentication"},
	// Privilege Escalation
	"269": {"privilege_escalation"},
	"250": {"privilege_escalation"},
	"266": {"privilege_escalation"},
	"732": {"privilege_escalation"},
	"665": {"privilege_escalation"},
	// SSRF
	"918": {"ssrf"},
	// CSRF
	"352": {"csrf"},
	// XXE
	"611": {"xxe"},
	// Access Control
	"639": {"authentication"},
	"284": {"authentication"},
}

// Enhanced attack vector keywords with grammatical variations
var attackVectorKeywords = map[string][]string{
	"sql_injection":        {"sql injection", "sqli", "sql query", "sql command"},
	"ldap_injection":       {"ldap injection", "ldap query", "ldap", "ldap endpoints", "ldap servers"},
	"command_injection":    {"command injection", "os command", "shell injection", "execute commands"},
	"code_injection":       {"code injection", "arbitrary code", "code execution"},
	"jndi_injection":       {"jndi", "jndi lookup", "jndi injection"},
	"template_injection":   {"template injection", "ssti", "server-side template"},
	"xss":                  {"cross-site scripting", "xss", "dom-based", "reflected xss", "stored xss", "javascript injection"},
	"deserialization":      {"deserialization", "deserialize", "unserialize", "pickle", "object injection", "serialized"},
	"buffer_overflow":      {"buffer overflow", "stack overflow", "heap overflow", "memory corruption", "overflow a buffer", "overflow a heap", "overflow a stack", "heap based buffer", "stack based buffer", "buffer overrun"},
	"path_traversal":       {"path traversal", "directory traversal", "file inclusion", "lfi", "rfi", "traverse directories", "access files outside"},
	"authentication":       {"authentication", "credential", "password", "login", "session", "bypass", "auth bypass"},
	"privilege_escalation": {"privilege escalation", "escalate privileges", "escalate their privileges", "elevate privileges", "privilege elevation", "gain elevated privileges", "gain higher privileges"},
	"csrf":                 {"csrf", "cross-site request forgery", "xsrf"},
	"ssrf":                 {"ssrf", "server-side request forgery"},
	"xxe":                  {"xxe", "xml external entity"},
	"rce":                  {"remote code execution", "rce", "execute arbitrary code", "arbitrary code execution", "execute code"},
	"dos":                  {"denial of service", "dos", "resource exhaustion"},
}

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

// ML Model structures for hybrid classifier
type CWEHierarchy struct {
	CWEs                map[string]*CWEHierarchyInfo `json:"cwes"`
	AttackVectorMapping map[string][]string          `json:"attack_vector_mapping"`
}

type CWEHierarchyInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Abstraction   string   `json:"abstraction"`
	Parents       []string `json:"parents"`
	Children      []string `json:"children"`
	AttackVectors []string `json:"attack_vectors"`
}

type AttackVectorModel struct {
	AttackVectors   []string                      `json:"attack_vectors"`
	VectorPriors    map[string]float64            `json:"vector_priors"`
	WordGivenVector map[string]map[string]float64 `json:"word_given_vector"`
	WordCounts      map[string]map[string]int     `json:"word_counts"`
	TotalWords      map[string]int                `json:"total_words"`
	Vocabulary      []string                      `json:"vocabulary"`
	TotalDocuments  int                           `json:"total_documents"`
	VectorDocCounts map[string]int                `json:"vector_doc_counts"`
}

type ClassificationResult struct {
	Vector      string  `json:"vector"`
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
	Confidence  string  `json:"confidence"`
	Source      string  `json:"source"`
}

// Granular attack vector structures
type AttackVectorTaxonomy struct {
	AttackVectors map[string]VectorTaxInfo `json:"attack_vectors"`
}

type VectorTaxInfo struct {
	Name     string                 `json:"name"`
	Subtypes map[string]SubtypeInfo `json:"subtypes"`
}

type SubtypeInfo struct {
	Name        string   `json:"name"`
	Keywords    []string `json:"keywords"`
	CAPECIDs    []string `json:"capec_ids"`
	Description string   `json:"description"`
}

type GranularResult struct {
	BaseVector     string
	SpecificType   string
	TypeName       string
	Confidence     float64
	MatchedTerms   []string
	RelevantCAPECs []string
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
	Data []EPSSDataWrapper `json:"data"`
}

type EPSSDataWrapper struct {
	CVE        string     `json:"cve"`
	EPSS       string     `json:"epss"`
	Percentile string     `json:"percentile"`
	Date       string     `json:"date"`
	TimeSeries []EPSSData `json:"time-series"`
}

type EPSSData struct {
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
	CVE              CVEItem
	BestAttackVector string // ML-detected best attack vector (e.g., "ssrf", "xss", "sql_injection")
	CWEs             []CWEDetail
	CAPECs           []CAPECDetail
	Techniques       []TechniqueDetail
	ThreatActors     []ThreatActorDetail
	AtomicTests      []AtomicTestDetail
	EPSS             EPSSDetail
	GeneratedAt      time.Time
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
	RelevanceScore     float64
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
	Source      string
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

// CAPEC scoring structure
type ScoredCAPEC struct {
	ID    string
	Info  CAPECInfo
	Score float64
}

func main() {
	flag.StringVar(&cveID, "cve", "", "CVE ID to query (e.g., CVE-2024-1234)")
	flag.StringVar(&outputHTML, "html", "", "Output HTML report file (optional)")
	flag.IntVar(&maxCAPECs, "max-capecs", 3, "Maximum number of CAPECs to include (default: 3)")
	flag.Parse()

	if cveID == "" {
		fmt.Println("Usage: cve-query -cve CVE-YYYY-NNNNN [-html output.html] [-max-capecs N]")
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

	// Load ML models (optional, graceful degradation)
	fmt.Println("Loading ML models...")
	loadMLModels(db)

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
		epssData = EPSSDetail{}
	}

	// Build report
	fmt.Println("Building attack chain with intelligent CAPEC filtering...")
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

	// Query with time-series scope
	url := fmt.Sprintf("%s?cve=%s&scope=time-series", EPSSAPI, cveID)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return detail, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return detail, fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var epssResp EPSSResponse
	if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
		return detail, fmt.Errorf("failed to parse EPSS response: %w", err)
	}

	if len(epssResp.Data) == 0 {
		return detail, fmt.Errorf("no EPSS data found")
	}

	wrapper := epssResp.Data[0]

	// Set current score
	detail.Current = EPSSData{
		EPSS:       wrapper.EPSS,
		Percentile: wrapper.Percentile,
		Date:       wrapper.Date,
	}

	// Set time series
	detail.TimeSeries = wrapper.TimeSeries

	return detail, nil
}

func buildReport(cve CVEItem, epss EPSSDetail, db *LocalDB) Report {
	report := Report{
		CVE:         cve,
		EPSS:        epss,
		GeneratedAt: time.Now(),
	}

	// Extract CVE description for context
	cveDescription := ""
	if len(cve.Descriptions) > 0 {
		cveDescription = cve.Descriptions[0].Value
	}

	// Extract CWE IDs
	allCWEIDs := extractCWEIDs(cve)

	// STEP 1: Detect best attack vector using ML
	detectedVectors := detectAttackVectors(cveDescription, allCWEIDs)
	fmt.Printf("  Detected attack vectors: %v\n", detectedVectors)

	// Store best attack vector for report
	bestAttackVector := ""
	if len(detectedVectors) > 0 {
		bestAttackVector = detectedVectors[0] // Top ranked vector
	}
	report.BestAttackVector = bestAttackVector

	// STEP 2: Find best matching CWEs using ML attack vector classification
	// Filter CWEs to only those related to the detected attack vectors
	bestCWEs := []string{}
	if mlEnabled && len(detectedVectors) > 0 {
		// Use ML to find most relevant CWEs for detected vectors
		for _, cweID := range allCWEIDs {
			// Check if this CWE maps to any detected vector
			if vectors, exists := cweToVector[cweID]; exists {
				for _, vec := range vectors {
					for _, detectedVec := range detectedVectors {
						if vec == detectedVec {
							bestCWEs = append(bestCWEs, cweID)
							break
						}
					}
				}
			}
		}
	}

	// Fallback: if no ML match, use all CWEs
	if len(bestCWEs) == 0 {
		bestCWEs = allCWEIDs
	}

	fmt.Printf("  Found %d CWEs (filtered to %d best matches)\n", len(allCWEIDs), len(bestCWEs))

	// Build CWE details (show only best matching CWEs)
	for _, cweID := range bestCWEs {
		if cweInfo, ok := db.CWEs[cweID]; ok {
			report.CWEs = append(report.CWEs, CWEDetail{
				ID:   cweID,
				Name: cweInfo.Name,
			})
		}
	}

	// Build CAPEC details with intelligent filtering
	capecCandidates := []ScoredCAPEC{}
	capecSet := make(map[string]bool)

	// STEP 3: Collect candidate CAPECs from best matching CWEs only
	for _, cweID := range bestCWEs {
		if capecIDs, ok := db.Relationships.CWEToCapec[cweID]; ok {
			for _, capecID := range capecIDs {
				if !capecSet[capecID] {
					capecSet[capecID] = true
					if capecInfo, ok := db.CAPECs[capecID]; ok {
						score := scoreCAPECRelevance(capecID, capecInfo, cveDescription, detectedVectors, db)
						capecCandidates = append(capecCandidates, ScoredCAPEC{
							ID:    capecID,
							Info:  capecInfo,
							Score: score,
						})
					}
				}
			}
		}
	}

	fmt.Printf("  Evaluating %d candidate CAPECs...\n", len(capecCandidates))

	// Sort by relevance score (descending)
	sort.Slice(capecCandidates, func(i, j int) bool {
		return capecCandidates[i].Score > capecCandidates[j].Score
	})

	// Take top N most relevant CAPECs
	topN := maxCAPECs
	if len(capecCandidates) < topN {
		topN = len(capecCandidates)
	}

	for i := 0; i < topN; i++ {
		sc := capecCandidates[i]
		report.CAPECs = append(report.CAPECs, CAPECDetail{
			ID:                 sc.ID,
			Name:               sc.Info.Name,
			Description:        sc.Info.Description,
			LikelihoodOfAttack: sc.Info.LikelihoodOfAttack,
			TypicalSeverity:    sc.Info.TypicalSeverity,
			Prerequisites:      sc.Info.Prerequisites,
			RelevanceScore:     sc.Score,
		})
	}

	fmt.Printf("  Selected top %d most relevant CAPECs\n", len(report.CAPECs))

	// Build Technique details (from CAPEC relationships)
	techniqueSet := make(map[string]bool)
	for _, capec := range report.CAPECs {
		if techIDs, ok := db.Relationships.CapecToAttack[capec.ID]; ok {
			for _, techID := range techIDs {
				techniqueSet[techID] = true
			}
		}
	}
	fmt.Printf("  Found %d ATT&CK techniques from CAPEC mappings\n", len(techniqueSet))

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
	fmt.Printf("  Found %d threat actors\n", len(actorSet))

	for _, actor := range actorSet {
		report.ThreatActors = append(report.ThreatActors, actor)
	}

	// Fetch Atomic Red Team tests
	fmt.Printf("  Fetching Atomic Red Team tests for %d techniques...\n", len(techniqueSet))
	for techID := range techniqueSet {
		tests := fetchAtomicTests(techID)
		if len(tests) > 0 {
			fmt.Printf("    %s: %d tests\n", techID, len(tests))
		}
		report.AtomicTests = append(report.AtomicTests, tests...)
	}
	fmt.Printf("  Total Atomic Red Team tests: %d\n", len(report.AtomicTests))

	return report
}

// Detect attack vectors using multi-layered approach (with ML when available)
func detectAttackVectors(description string, cweIDs []string) []string {
	// Use ML-based detection if models are loaded
	if mlEnabled {
		return detectAttackVectorsML(description, cweIDs)
	}

	// Fallback to keyword-based detection
	vectorConfidence := make(map[string]int)

	// Layer 1: CWE Mapping (confidence: 100)
	for _, cweID := range cweIDs {
		if vectors, ok := cweToVector[cweID]; ok {
			for _, vector := range vectors {
				if vectorConfidence[vector] < 100 {
					vectorConfidence[vector] = 100
				}
			}
		}
	}

	descriptionLower := strings.ToLower(description)

	// Layer 2: Enhanced Keyword Matching (confidence: 90)
	for vector, keywords := range attackVectorKeywords {
		for _, keyword := range keywords {
			if strings.Contains(descriptionLower, keyword) {
				if vectorConfidence[vector] < 90 {
					vectorConfidence[vector] = 90
				}
				break
			}
		}
	}

	// Layer 3: Pattern-based detection (confidence: 80)
	// Buffer overflow patterns
	if matchesPattern(description, `(?i)overflow.*(?:heap|stack|buffer)`) ||
		matchesPattern(description, `(?i)(?:heap|stack|buffer).*overflow`) ||
		matchesPattern(description, `(?i)memory\s+corruption`) {
		if vectorConfidence["buffer_overflow"] < 80 {
			vectorConfidence["buffer_overflow"] = 80
		}
	}

	// Privilege escalation patterns
	if matchesPattern(description, `(?i)escalate.*privilege`) ||
		matchesPattern(description, `(?i)elevate.*privilege`) ||
		matchesPattern(description, `(?i)gain.*(?:elevated|higher|admin).*privilege`) {
		if vectorConfidence["privilege_escalation"] < 80 {
			vectorConfidence["privilege_escalation"] = 80
		}
	}

	// Path traversal patterns
	if matchesPattern(description, `(?i)(?:path|directory)\s+traversal`) ||
		matchesPattern(description, `(?i)traverse.*(?:path|director(?:y|ies))`) ||
		matchesPattern(description, `(?i)access.*(?:file|director(?:y|ies)).*outside`) {
		if vectorConfidence["path_traversal"] < 80 {
			vectorConfidence["path_traversal"] = 80
		}
	}

	// Return vectors with confidence >= 70
	var detectedVectors []string
	for vector, confidence := range vectorConfidence {
		if confidence >= 70 {
			detectedVectors = append(detectedVectors, vector)
		}
	}

	return detectedVectors
}

// Helper function for regex pattern matching
func matchesPattern(text, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(text)
}

// Score CAPEC relevance using Naive Bayes + Jaccard similarity
func scoreCAPECRelevance(capecID string, capec CAPECInfo, cveDesc string, detectedVectors []string, db *LocalDB) float64 {
	// If CAPEC training data is available, use Naive Bayes + Jaccard similarity
	if capecData != nil && len(capecData) > 0 {
		if capecInfo, exists := capecData[capecID]; exists {
			// Calculate Jaccard similarity (Naive Bayes approach)
			similarity := calculateCAPECSimilarity(cveDesc, capecInfo)
			// Scale to 0-100 range
			return similarity * 100.0
		}
		// Debug: CAPEC ID not found in training data, falling back to keyword scoring
		// This happens when the CAPEC exists in capec_db.json but not in capec_training_data.json
	}

	// Fallback to keyword-based scoring if CAPEC data not available
	score := 0.0

	capecName := strings.ToLower(capec.Name)
	capecDesc := strings.ToLower(capec.Description)
	combinedText := capecName + " " + capecDesc

	// Apply granular classification for each detected vector
	granularBoosts := make(map[string]float64)
	if taxonomy != nil {
		for _, vector := range detectedVectors {
			granular := classifyGranular(vector, cveDesc)
			if granular.Confidence > 0.3 && len(granular.RelevantCAPECs) > 0 {
				for _, relevantCAPEC := range granular.RelevantCAPECs {
					granularBoosts[relevantCAPEC] = granular.Confidence * 100.0
				}
			}
		}
	}

	// Factor 1: Has ATT&CK mappings (strongly prefer these)
	if len(capec.MitreAttack) > 0 {
		score += 50.0
	}

	// Factor 2: Match with detected attack vectors
	for _, vector := range detectedVectors {
		keywords := attackVectorKeywords[vector]
		for _, keyword := range keywords {
			if strings.Contains(combinedText, keyword) {
				score += 20.0
				break
			}
		}
	}

	// Factor 3: Keyword matching with CVE description
	cveWords := extractSignificantWords(cveDesc)
	matchCount := 0
	for _, word := range cveWords {
		if len(word) > 4 && strings.Contains(combinedText, word) {
			matchCount++
		}
	}
	score += float64(matchCount) * 2.0

	// Factor 4: Likelihood and severity
	if capec.LikelihoodOfAttack == "High" {
		score += 5.0
	} else if capec.LikelihoodOfAttack == "Medium" {
		score += 2.0
	}

	if capec.TypicalSeverity == "Very High" {
		score += 5.0
	} else if capec.TypicalSeverity == "High" {
		score += 3.0
	}

	// Factor 5: Penalize overly specific patterns when not detected (MUCH STRONGER)
	specificPatterns := map[string][]string{
		"xss":             {"cross-site scripting", "xss", "dom-based", "javascript injection"},
		"csrf":            {"cross-site request forgery", "csrf", "xsrf"},
		"sql_injection":   {"sql injection", "sqli", "blind sql"},
		"deserialization": {"deserialization", "deserialize", "object injection", "serialized"},
		"ssrf":            {"ssrf", "server-side request forgery"},
		"buffer_overflow": {"buffer overflow", "stack overflow", "heap overflow"},
		"path_traversal":  {"path traversal", "directory traversal"},
	}

	for vectorType, patterns := range specificPatterns {
		// If this specific vector wasn't detected in CVE, heavily penalize CAPECs related to it
		vectorDetected := false
		for _, v := range detectedVectors {
			if v == vectorType {
				vectorDetected = true
				break
			}
		}

		if !vectorDetected {
			for _, pattern := range patterns {
				if strings.Contains(combinedText, pattern) {
					score -= 100.0 // VERY heavy penalty to eliminate irrelevant patterns
					break
				}
			}
		}
	}

	// Factor 6: Granular classification boost (NEW - highest priority)
	// Check if this CAPEC ID matches any granularly-identified relevant CAPECs
	for boostCAPECID, boostScore := range granularBoosts {
		if capecID == boostCAPECID {
			score += boostScore
			break
		}
	}

	return score
}

// Extract significant words from text (filter out common words)
func extractSignificantWords(text string) []string {
	commonWords := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "that": true,
		"this": true, "from": true, "can": true, "are": true, "has": true,
		"have": true, "when": true, "where": true, "which": true, "who": true,
		"will": true, "would": true, "could": true, "should": true,
	}

	words := strings.Fields(text)
	significant := []string{}

	for _, word := range words {
		word = strings.Trim(word, ".,;:!?()[]{}\"'")
		if len(word) > 3 && !commonWords[word] {
			significant = append(significant, word)
		}
	}

	return significant
}

func extractCWEIDs(cve CVEItem) []string {
	cweSet := make(map[string]bool)

	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
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

	url := fmt.Sprintf("%s/%s/%s.yaml", AtomicRedTeamBaseURL, techniqueID, techniqueID)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return tests
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

	// ML-Detected Attack Vector
	if report.BestAttackVector != "" {
		fmt.Printf("\n[ML-DETECTED ATTACK VECTOR]\n")
		fmt.Printf("🎯 Primary Attack Type: %s (ML-Classified)\n", strings.ToUpper(report.BestAttackVector))
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
		fmt.Printf("\n[MOST RELEVANT ATTACK PATTERNS (CAPEC)] (Top %d)\n", len(report.CAPECs))
		for _, capec := range report.CAPECs {
			fmt.Printf("  • CAPEC-%s: %s (Relevance: %.1f)\n", capec.ID, capec.Name, capec.RelevanceScore)
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

        .relevance-score {
            display: inline-block;
            padding: 4px 12px;
            margin-left: 10px;
            background: #28a745;
            color: white;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
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

        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #0066cc;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
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

	// ML-Detected Attack Vector
	if report.BestAttackVector != "" {
		html += fmt.Sprintf(`
            <!-- ML-Detected Attack Vector -->
            <div class="section" style="border-left: 4px solid #ff6b6b;">
                <h2>🎯 ML-Detected Attack Vector</h2>
                <div class="info-box" style="background: #fff5f5; border-left-color: #ff6b6b;">
                    <p style="font-size: 1.3em; font-weight: bold; color: #c92a2a;">
                        Primary Attack Type: %s
                        <span class="badge" style="background: #ff6b6b; margin-left: 10px;">ML-Classified</span>
                    </p>
                    <p style="margin-top: 10px; color: #666;">
                        This attack vector was automatically detected using hybrid ML classification combining CWE hierarchy analysis and Naive Bayes text classification.
                    </p>
                </div>
            </div>`, strings.ToUpper(report.BestAttackVector))
	}

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
                <h2>Most Relevant Attack Patterns (CAPEC)<span class="badge badge-count">Top %d</span></h2>
                <div class="info-box">
                    <strong>ℹ️ Intelligent Filtering:</strong> These attack patterns were selected using a hybrid scoring system that considers CVE context, ATT&CK mappings, and keyword relevance to show only the most applicable patterns.
                </div>
                <ul class="item-list">`, len(report.CAPECs))
		for _, capec := range report.CAPECs {
			html += fmt.Sprintf(`
                    <li>
                        <strong>CAPEC-%s</strong>: %s
                        <span class="relevance-score">Relevance: %.1f</span>
                        <div class="details">%s</div>`, capec.ID, capec.Name, capec.RelevanceScore, capec.Description)
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
            <p>Report generated by CVE Query Tool with Intelligent CAPEC Filtering | %s</p>
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

// Load ML models for hybrid classification
func loadMLModels(db *LocalDB) {
	mlEnabled = false

	// Try to load CWE hierarchy
	hierarchyData, err := os.ReadFile("resources/cwe_hierarchy.json")
	if err != nil {
		fmt.Printf("  Warning: cwe_hierarchy.json not found (ML classification disabled)\n")
		return
	}

	var hierarchy CWEHierarchy
	if err := json.Unmarshal(hierarchyData, &hierarchy); err != nil {
		fmt.Printf("  Warning: Failed to parse cwe_hierarchy.json: %v\n", err)
		return
	}
	cweHierarchy = &hierarchy

	// Try to load Naive Bayes model
	modelData, err := os.ReadFile("resources/naive_bayes_model.json")
	if err != nil {
		fmt.Printf("  Warning: naive_bayes_model.json not found (ML classification disabled)\n")
		return
	}

	var model AttackVectorModel
	if err := json.Unmarshal(modelData, &model); err != nil {
		fmt.Printf("  Warning: Failed to parse naive_bayes_model.json: %v\n", err)
		return
	}
	nbModel = &model

	// Try to load attack vector taxonomy
	taxonomyData, err := os.ReadFile("resources/attack_vector_taxonomy.json")
	if err != nil {
		fmt.Printf("  Warning: attack_vector_taxonomy.json not found (granular classification disabled)\n")
	} else {
		var tax AttackVectorTaxonomy
		if err := json.Unmarshal(taxonomyData, &tax); err != nil {
			fmt.Printf("  Warning: Failed to parse attack_vector_taxonomy.json: %v\n", err)
		} else {
			taxonomy = &tax
			fmt.Printf("  Granular taxonomy loaded (%d base vectors)\n", len(tax.AttackVectors))
		}
	}

	// Load CAPEC data from capec_db.json (already loaded in db.CAPECs)
	// Convert to CAPECTrainingData format for Naive Bayes ranking
	capecData = make(map[string]CAPECTrainingData)
	for capecID, capecInfo := range db.CAPECs {
		capecData[capecID] = CAPECTrainingData{
			CAPECID:            capecID,
			Name:               capecInfo.Name,
			Description:        capecInfo.Description,
			LikelihoodOfAttack: capecInfo.LikelihoodOfAttack,
			TypicalSeverity:    capecInfo.TypicalSeverity,
			RelatedCWEs:        capecInfo.RelatedWeaknesses,
			Prerequisites:      capecInfo.Prerequisites,
		}
	}
	fmt.Printf("  CAPEC ranking data loaded (%d CAPECs)\n", len(capecData))

	mlEnabled = true
	fmt.Printf("  ML models loaded successfully (%d attack vectors)\n", len(model.VectorPriors))
}

// Hybrid ML-based attack vector detection
func detectAttackVectorsML(description string, cweIDs []string) []string {
	// Get candidates from CWE hierarchy
	candidates := getCandidatesFromCWEsML(cweIDs)

	// Classify using Naive Bayes
	var results []ClassificationResult
	if len(candidates) > 0 {
		results = classifyNaiveBayesML(description, candidates)
	} else {
		results = classifyNaiveBayesML(description, nil)
	}

	// Filter and extract top vectors
	var vectors []string
	for _, result := range results {
		if result.Probability >= 0.0001 && len(vectors) < 5 {
			vectors = append(vectors, result.Vector)
		}
	}

	return vectors
}

func getCandidatesFromCWEsML(cweIDs []string) map[string]bool {
	candidates := make(map[string]bool)

	if cweHierarchy == nil || len(cweIDs) == 0 {
		return candidates
	}

	for _, cweID := range cweIDs {
		cwe, exists := cweHierarchy.CWEs[cweID]
		if !exists {
			continue
		}

		// Level 0: Direct mapping
		for _, vector := range cwe.AttackVectors {
			candidates[vector] = true
		}

		// Level 1: Parent mappings
		for _, parentID := range cwe.Parents {
			parent, exists := cweHierarchy.CWEs[parentID]
			if !exists {
				continue
			}
			for _, vector := range parent.AttackVectors {
				candidates[vector] = true
			}

			// Level 2: Grandparent mappings
			for _, grandparentID := range parent.Parents {
				grandparent, exists := cweHierarchy.CWEs[grandparentID]
				if !exists {
					continue
				}
				for _, vector := range grandparent.AttackVectors {
					candidates[vector] = true
				}
			}
		}
	}

	return candidates
}

func classifyNaiveBayesML(description string, candidates map[string]bool) []ClassificationResult {
	if nbModel == nil {
		return []ClassificationResult{}
	}

	// Tokenize description
	tokens := tokenizeML(description)

	// Calculate log probabilities
	scores := make(map[string]float64)

	for vector := range nbModel.VectorPriors {
		// Skip if not in candidates
		if candidates != nil && len(candidates) > 0 && !candidates[vector] {
			continue
		}

		// Start with prior
		logProb := math.Log(nbModel.VectorPriors[vector])

		// Add word probabilities
		for _, word := range tokens {
			if prob, exists := nbModel.WordGivenVector[vector][word]; exists {
				logProb += math.Log(prob)
			}
		}

		scores[vector] = logProb
	}

	// Convert to probabilities
	results := make([]ClassificationResult, 0, len(scores))

	maxLogProb := math.Inf(-1)
	for _, logProb := range scores {
		if logProb > maxLogProb {
			maxLogProb = logProb
		}
	}

	sumProb := 0.0
	probs := make(map[string]float64)
	for vector, logProb := range scores {
		prob := math.Exp(logProb - maxLogProb)
		probs[vector] = prob
		sumProb += prob
	}

	// Normalize and create results
	for vector, prob := range probs {
		normalizedProb := prob / sumProb

		confidence := "low"
		if normalizedProb >= 0.7 {
			confidence = "high"
		} else if normalizedProb >= 0.4 {
			confidence = "medium"
		}

		results = append(results, ClassificationResult{
			Vector:      vector,
			Probability: normalizedProb,
			Confidence:  confidence,
		})
	}

	// Sort by probability
	sort.Slice(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	return results
}

func tokenizeML(text string) []string {
	text = strings.ToLower(text)

	// Remove version numbers and CVE IDs
	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")
	cveRegex := regexp.MustCompile(`\bcve-\d{4}-\d+\b`)
	text = cveRegex.ReplaceAllString(text, "")

	// Extract words
	wordRegex := regexp.MustCompile(`[a-z]{3,}`)
	words := wordRegex.FindAllString(text, -1)

	// Filter stopwords
	stopwords := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"that": true, "this": true, "are": true, "was": true, "were": true,
		"been": true, "being": true, "have": true, "has": true, "had": true,
		"but": true, "not": true, "can": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true,
		"vulnerability": true, "vulnerabilities": true, "vulnerable": true,
		"issue": true, "issues": true, "flaw": true, "flaws": true,
		"product": true, "products": true, "component": true, "components": true,
		"application": true, "applications": true, "software": true,
		"version": true, "versions": true, "release": true, "releases": true,
		"attacker": true, "attackers": true, "user": true, "users": true,
		"access": true, "system": true, "systems": true,
		"data": true, "code": true, "file": true, "files": true,
		"allows": true, "allow": true, "via": true,
		"perform": true, "execute": true, "run": true, "process": true,
	}

	filtered := make([]string, 0, len(words))
	for _, word := range words {
		if !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// Classify granular attack vector subtype
func classifyGranular(baseVector, description string) GranularResult {
	result := GranularResult{
		BaseVector:     baseVector,
		SpecificType:   baseVector,
		Confidence:     0.0,
		MatchedTerms:   []string{},
		RelevantCAPECs: []string{},
	}

	if taxonomy == nil {
		result.TypeName = "Unknown"
		return result
	}

	// Get vector info
	vectorInfo, exists := taxonomy.AttackVectors[baseVector]
	if !exists {
		result.TypeName = "Unknown"
		return result
	}

	descLower := strings.ToLower(description)

	// Score each subtype
	scores := make(map[string]float64)
	matches := make(map[string][]string)

	for subtypeID, subtype := range vectorInfo.Subtypes {
		score := 0.0
		matched := []string{}

		for _, keyword := range subtype.Keywords {
			if strings.Contains(descLower, strings.ToLower(keyword)) {
				score += 1.0
				matched = append(matched, keyword)
			}
		}

		if score > 0 {
			scores[subtypeID] = score
			matches[subtypeID] = matched
		}
	}

	// Find best match
	bestScore := 0.0
	bestSubtype := ""

	for subtypeID, score := range scores {
		if score > bestScore {
			bestScore = score
			bestSubtype = subtypeID
		}
	}

	// If we found a match
	if bestSubtype != "" {
		subtype := vectorInfo.Subtypes[bestSubtype]
		result.SpecificType = bestSubtype
		result.TypeName = subtype.Name
		result.Confidence = bestScore / float64(len(subtype.Keywords))
		result.MatchedTerms = matches[bestSubtype]
		result.RelevantCAPECs = subtype.CAPECIDs
	} else {
		// No specific subtype found, use generic
		result.TypeName = vectorInfo.Name
		result.Confidence = 0.5 // Medium confidence for generic classification
	}

	return result
}

// Calculate Naive Bayes similarity using Jaccard similarity (same as phase3-classifier)
func calculateCAPECSimilarity(cveDesc string, capecInfo CAPECTrainingData) float64 {
	// Tokenize both descriptions
	cveTokens := tokenizeForRanking(cveDesc)
	capecText := capecInfo.Description + " " + capecInfo.Name + " " + strings.Join(capecInfo.Prerequisites, " ")
	capecTokens := tokenizeForRanking(capecText)

	// Create sets for Jaccard similarity
	cveSet := make(map[string]bool)
	for _, token := range cveTokens {
		cveSet[token] = true
	}

	capecSet := make(map[string]bool)
	for _, token := range capecTokens {
		capecSet[token] = true
	}

	// Calculate Jaccard similarity: intersection / union
	intersection := 0
	for token := range cveSet {
		if capecSet[token] {
			intersection++
		}
	}

	union := len(cveSet) + len(capecSet) - intersection
	if union == 0 {
		return 0.0
	}

	jaccardSim := float64(intersection) / float64(union)

	// Boost if severity is high (same as phase3-classifier)
	if capecInfo.TypicalSeverity == "High" || capecInfo.TypicalSeverity == "Very High" {
		jaccardSim *= 1.2
	}

	return jaccardSim
}

func tokenizeForRanking(text string) []string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove version numbers and CVE IDs
	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")
	cveRegex := regexp.MustCompile(`\bcve-\d{4}-\d+\b`)
	text = cveRegex.ReplaceAllString(text, "")

	// Extract words (3+ characters)
	wordRegex := regexp.MustCompile(`[a-z]{3,}`)
	words := wordRegex.FindAllString(text, -1)

	// Filter stopwords
	stopwords := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"that": true, "this": true, "are": true, "was": true, "were": true,
		"been": true, "being": true, "have": true, "has": true, "had": true,
		"but": true, "not": true, "can": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true,
	}

	filtered := make([]string, 0, len(words))
	for _, word := range words {
		if !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}
