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
)

// NVD API structures
type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// CWE Hierarchy structures
type CWEInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Abstraction   string   `json:"abstraction"`
	Parents       []string `json:"parents"`
	Children      []string `json:"children"`
	AttackVectors []string `json:"attack_vectors"`
}

type CWEHierarchy struct {
	CWEs                map[string]*CWEInfo `json:"cwes"`
	AttackVectorMapping map[string][]string `json:"attack_vector_mapping"`
}

// Naive Bayes model structures (matching trainer output)
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

// Classification result
type ClassificationResult struct {
	Vector      string  `json:"vector"`
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
	Confidence  string  `json:"confidence"`
	Source      string  `json:"source"` // "cwe_hierarchy", "naive_bayes", or "hybrid"
}

// CAPEC structures
type CAPECData struct {
	CAPECID         string   `json:"capec_id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	RelatedCWEs     []string `json:"related_cwes"`
	TypicalSeverity string   `json:"typical_severity"`
}

// CWE to CAPEC relationships
type RelationshipsDB struct {
	CWEToCapec    map[string][]string `json:"CWEToCapec"`
	CapecToAttack map[string][]string `json:"CapecToAttack"`
}

// CAPEC ranking result
type CAPECResult struct {
	CAPECID     string  `json:"capec_id"`
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
	Confidence  string  `json:"confidence"`
}

// ScoredCWE represents a CWE with its relevance score
type ScoredCWE struct {
	ID    string
	Score float64
}

var (
	cveID       string
	cveDesc     string
	cweIDs      string
	topN        int
	showDetails bool
)

func main() {
	flag.StringVar(&cveID, "cve", "", "CVE ID (e.g., 'CVE-2021-44228')")
	flag.StringVar(&cveDesc, "description", "", "CVE description text (alternative to -cve)")
	flag.StringVar(&cveDesc, "d", "", "CVE description text (shorthand)")
	flag.StringVar(&cweIDs, "cwes", "", "Comma-separated CWE IDs (e.g., '94,502,20')")
	flag.StringVar(&cweIDs, "c", "", "Comma-separated CWE IDs (shorthand)")
	flag.IntVar(&topN, "top", 3, "Number of top results to return")
	flag.BoolVar(&showDetails, "verbose", false, "Show detailed classification process")
	flag.BoolVar(&showDetails, "v", false, "Show detailed classification process (shorthand)")
	flag.Parse()

	if cveID == "" && cveDesc == "" {
		fmt.Println("Usage:")
		fmt.Println("  phase3-classifier -cve CVE-2021-44228 [-top 3] [-verbose]")
		fmt.Println("  phase3-classifier -description \"CVE description\" [-cwes \"94,502\"] [-top 3] [-verbose]")
		fmt.Println("\nExamples:")
		fmt.Println("  phase3-classifier -cve CVE-2021-44228")
		fmt.Println("  phase3-classifier -d \"allows remote attackers to execute arbitrary code via JNDI\" -c \"502,917\"")
		os.Exit(1)
	}

	fmt.Println("=================================================================")
	fmt.Println("Hybrid CWE + Naive Bayes Attack Vector Classifier")
	fmt.Println("=================================================================\n")

	// If CVE ID is provided, fetch from NVD
	var cwes []string
	if cveID != "" {
		if showDetails {
			fmt.Printf("Fetching CVE data from NVD API for %s...\n", cveID)
		}

		description, cweList, err := fetchCVEFromNVD(cveID)
		if err != nil {
			fmt.Printf("Error fetching CVE data: %v\n", err)
			os.Exit(1)
		}

		cveDesc = description
		cwes = cweList

		fmt.Printf("CVE ID: %s\n", cveID)
		fmt.Printf("Description: %s\n", cveDesc)
		if len(cwes) > 0 {
			fmt.Printf("CWE IDs: %s\n\n", strings.Join(cwes, ", "))
		} else {
			fmt.Println("CWE IDs: (none found)\n")
		}
	} else {
		// Parse CWE IDs from command line
		if cweIDs != "" {
			cwes = strings.Split(strings.ReplaceAll(cweIDs, " ", ""), ",")
			// Clean CWE IDs (remove "CWE-" prefix if present)
			for i, cwe := range cwes {
				cwes[i] = strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")
			}
		}
	}

	// Load CWE hierarchy
	if showDetails {
		fmt.Println("Loading CWE hierarchy...")
	}
	hierarchy, err := loadCWEHierarchy("resources/cwe_hierarchy.json")
	if err != nil {
		fmt.Printf("Error loading CWE hierarchy: %v\n", err)
		fmt.Println("Run 'cwe-builder' first to generate resources/cwe_hierarchy.json")
		os.Exit(1)
	}
	if showDetails {
		fmt.Printf("Loaded %d CWEs\n\n", len(hierarchy.CWEs))
	}

	// Load Naive Bayes model
	if showDetails {
		fmt.Println("Loading Naive Bayes model...")
	}
	model, err := loadNaiveBayesModel("resources/naive_bayes_model.json")
	if err != nil {
		fmt.Printf("Error loading Naive Bayes model: %v\n", err)
		fmt.Println("Run 'trainer' first to generate resources/naive_bayes_model.json")
		os.Exit(1)
	}
	if showDetails {
		fmt.Printf("Loaded model with %d attack vectors\n\n", len(model.VectorPriors))
	}

	// Classify
	results := classifyHybrid(cveDesc, cwes, hierarchy, model, topN, showDetails)

	// Display results
	fmt.Println("\n=================================================================")
	fmt.Println("Classification Results:")
	fmt.Println("=================================================================\n")

	for i, result := range results {
		fmt.Printf("%d. %s\n", i+1, result.Name)
		fmt.Printf("   Probability: %.2f%% (%s confidence)\n", result.Probability*100, result.Confidence)
		fmt.Printf("   Source: %s\n", result.Source)
		if i < len(results)-1 {
			fmt.Println()
		}
	}

	// CAPEC Ranking
	if len(results) > 0 && len(cwes) > 0 {
		// Load CAPEC data
		if showDetails {
			fmt.Println("\nLoading CAPEC data...")
		}
		capecData, err := loadCAPECData("resources/capec_training_data.json")
		if err != nil {
			if showDetails {
				fmt.Printf("Warning: Could not load CAPEC data: %v\n", err)
			}
		} else {
			// Load relationships
			relationships, err := loadRelationships("resources/relationships_db.json")
			if err != nil {
				if showDetails {
					fmt.Printf("Warning: Could not load relationships: %v\n", err)
				}
			} else {
				// Rank CAPECs using the best CWEs
				capecResults := rankCAPECs(cveDesc, cwes, capecData, relationships, 2, showDetails)

				// Display CAPEC results
				if len(capecResults) > 0 {
					fmt.Println("\n==================================================================")
					fmt.Println("Best Matching CAPECs:")
					fmt.Println("=================================================================\n")

					for i, capec := range capecResults {
						fmt.Printf("%d. CAPEC-%s: %s\n", i+1, capec.CAPECID, capec.Name)
						fmt.Printf("   Probability: %.2f%% (%s confidence)\n", capec.Probability*100, capec.Confidence)
						if i < len(capecResults)-1 {
							fmt.Println()
						}
					}
				}
			}
		}
	}
}

func fetchCVEFromNVD(cveID string) (string, []string, error) {
	// Normalize CVE ID
	cveID = strings.ToUpper(cveID)
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	// Build NVD API URL
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Make request
	resp, err := client.Get(url)
	if err != nil {
		return "", nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse JSON
	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return "", nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return "", nil, fmt.Errorf("CVE not found in NVD")
	}

	cve := nvdResp.Vulnerabilities[0].CVE

	// Extract description (prefer English)
	description := ""
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}
	if description == "" && len(cve.Descriptions) > 0 {
		description = cve.Descriptions[0].Value
	}

	// Extract CWE IDs
	var cweList []string
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			// CWE IDs are in format "CWE-123"
			if strings.HasPrefix(desc.Value, "CWE-") {
				cweID := strings.TrimPrefix(desc.Value, "CWE-")
				cweList = append(cweList, cweID)
			}
		}
	}

	return description, cweList, nil
}

// rankCWEsByRelevance scores and ranks CWEs based on their relevance to the CVE description
// Returns the top N CWEs sorted by relevance score (descending)
func rankCWEsByRelevance(cweIDs []string, description string, hierarchy *CWEHierarchy, topN int) []string {
	if len(cweIDs) == 0 {
		return []string{}
	}

	// Score each CWE
	scoredCWEs := []ScoredCWE{}
	descLower := strings.ToLower(description)

	for _, cweID := range cweIDs {
		score := scoreCWERelevance(cweID, descLower, hierarchy)
		scoredCWEs = append(scoredCWEs, ScoredCWE{
			ID:    cweID,
			Score: score,
		})
	}

	// Sort by score (descending)
	sort.Slice(scoredCWEs, func(i, j int) bool {
		return scoredCWEs[i].Score > scoredCWEs[j].Score
	})

	// Take top N
	resultCount := topN
	if len(scoredCWEs) < topN {
		resultCount = len(scoredCWEs)
	}

	result := make([]string, resultCount)
	for i := 0; i < resultCount; i++ {
		result[i] = scoredCWEs[i].ID
	}

	return result
}

// scoreCWERelevance calculates a relevance score for a CWE based on the CVE description
func scoreCWERelevance(cweID string, descLower string, hierarchy *CWEHierarchy) float64 {
	cwe, exists := hierarchy.CWEs[cweID]
	if !exists {
		return 0.0
	}

	score := 0.0
	cweName := strings.ToLower(cwe.Name)

	// 1. Base keyword matching
	keywords := extractCWEKeywords(cweName)
	for _, keyword := range keywords {
		if len(keyword) < 3 {
			continue
		}
		if strings.Contains(descLower, keyword) {
			score += 10.0
		}
	}

	// 2. Priority boost for critical CWEs
	priorityCWEs := map[string]float64{
		"502": 50.0, "78": 45.0, "79": 40.0, "89": 45.0, "94": 45.0,
		"77": 40.0, "22": 35.0, "434": 35.0, "611": 35.0, "918": 40.0,
		"917": 40.0, "119": 30.0, "787": 30.0, "416": 30.0, "352": 25.0,
		"306": 25.0, "862": 25.0,
	}
	if boost, exists := priorityCWEs[cweID]; exists {
		score += boost
	}

	// 3. Pattern-based boosting
	if containsAnyPattern(descLower, []string{"deserializ", "jndi", "ldap", "lookup", "unmarsh", "pickle"}) {
		if cweID == "502" {
			score += 100.0
		}
		if cweID == "917" {
			score += 50.0
		}
	}

	if containsAnyPattern(descLower, []string{"inject", "execut", "eval", "code execution"}) {
		if containsAnyPattern(descLower, []string{"code", "arbitrary"}) && cweID == "94" {
			score += 80.0
		}
		if containsAnyPattern(descLower, []string{"command", "shell", "os"}) && (cweID == "78" || cweID == "77") {
			score += 80.0
		}
	}

	if containsAnyPattern(descLower, []string{"sql", "database", "query"}) && cweID == "89" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"xss", "cross-site scripting", "script injection"}) && cweID == "79" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"path traversal", "directory traversal", "../", "..\\", "path manipulation"}) && cweID == "22" {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"ssrf", "server-side request", "internal request", "url fetch"}) && cweID == "918" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"xxe", "xml external entity", "xml injection"}) && cweID == "611" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"buffer overflow", "buffer overrun", "heap overflow", "stack overflow"}) && (cweID == "119" || cweID == "787") {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"authentication bypass", "auth bypass", "without authentication"}) && cweID == "306" {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"authorization bypass", "privilege escalation", "unauthorized access"}) && (cweID == "862" || cweID == "269") {
		score += 80.0
	}

	// 4. Penalty for generic CWEs
	genericCWEs := map[string]float64{
		"20": -20.0, "400": -15.0, "703": -20.0, "707": -20.0,
	}
	if penalty, exists := genericCWEs[cweID]; exists {
		score += penalty
	}

	// 5. Boost for CWEs with attack vector mappings
	if len(cwe.AttackVectors) > 0 {
		score += float64(len(cwe.AttackVectors)) * 5.0
	}

	if score < 0 {
		score = 0
	}

	return score
}

// extractCWEKeywords extracts meaningful keywords from CWE name
func extractCWEKeywords(text string) []string {
	stopWords := map[string]bool{
		"improper": true, "insufficient": true, "incorrect": true,
		"missing": true, "lack": true, "inadequate": true,
		"the": true, "of": true, "in": true, "to": true, "for": true,
		"and": true, "or": true, "a": true, "an": true,
	}

	re := regexp.MustCompile(`[^a-z0-9]+`)
	words := re.Split(text, -1)

	keywords := []string{}
	for _, word := range words {
		if len(word) >= 3 && !stopWords[word] {
			keywords = append(keywords, word)
		}
	}

	return keywords
}

// containsAnyPattern checks if the text contains any of the patterns
func containsAnyPattern(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func classifyHybrid(description string, cweIDs []string, hierarchy *CWEHierarchy, model *AttackVectorModel, topN int, verbose bool) []ClassificationResult {
	// Step 1: Rank CWEs by relevance and select top 2
	rankedCWEs := rankCWEsByRelevance(cweIDs, description, hierarchy, 2)

	if verbose && len(cweIDs) > 0 {
		fmt.Printf("\nCWE Ranking (top 2 of %d):\n", len(cweIDs))
		for i, cweID := range rankedCWEs {
			if cwe, exists := hierarchy.CWEs[cweID]; exists {
				score := scoreCWERelevance(cweID, strings.ToLower(description), hierarchy)
				fmt.Printf("  %d. CWE-%s: %s (score: %.1f)\n", i+1, cweID, cwe.Name, score)
			}
		}
	}

	// Step 2: Get candidate attack vectors from top 2 CWEs only
	candidates := getCandidatesFromCWEs(rankedCWEs, hierarchy, verbose)

	// Step 3: Apply Naive Bayes
	if len(candidates) > 0 {
		if verbose {
			fmt.Printf("\nApplying Naive Bayes to %d candidate attack vectors...\n", len(candidates))
		}
		// Classify only among candidates
		results := classifyNaiveBayes(description, model, candidates)

		// Filter out 0.00% probability results
		filteredResults := []ClassificationResult{}
		for _, result := range results {
			if result.Probability >= 0.0001 { // Filter out essentially zero probabilities
				filteredResults = append(filteredResults, result)
			}
		}
		results = filteredResults

		// Take top N
		if len(results) > topN {
			results = results[:topN]
		}

		// Mark as hybrid
		for i := range results {
			results[i].Source = "hybrid (CWE + Naive Bayes)"
		}

		return results
	} else {
		if verbose {
			fmt.Println("\nNo CWE IDs provided or no mappings found. Falling back to full Naive Bayes...")
		}
		// Fallback: classify among all vectors
		results := classifyNaiveBayes(description, model, nil)

		// Filter out 0.00% probability results
		filteredResults := []ClassificationResult{}
		for _, result := range results {
			if result.Probability >= 0.0001 { // Filter out essentially zero probabilities
				filteredResults = append(filteredResults, result)
			}
		}
		results = filteredResults

		// Take top N
		if len(results) > topN {
			results = results[:topN]
		}

		// Mark as naive bayes only
		for i := range results {
			results[i].Source = "naive_bayes (no CWE data)"
		}

		return results
	}
}

func getCandidatesFromCWEs(cweIDs []string, hierarchy *CWEHierarchy, verbose bool) map[string]bool {
	candidates := make(map[string]bool)

	if len(cweIDs) == 0 {
		return candidates
	}

	if verbose {
		fmt.Printf("\nExtracting candidate attack vectors from %d CWE IDs...\n", len(cweIDs))
	}

	for _, cweID := range cweIDs {
		// Get CWE info
		cwe, exists := hierarchy.CWEs[cweID]
		if !exists {
			if verbose {
				fmt.Printf("  CWE-%s: not found in hierarchy\n", cweID)
			}
			continue
		}

		if verbose {
			fmt.Printf("  CWE-%s (%s):\n", cweID, cwe.Name)
		}

		// Level 0: Direct mapping
		if len(cwe.AttackVectors) > 0 {
			for _, vector := range cwe.AttackVectors {
				candidates[vector] = true
				if verbose {
					fmt.Printf("    [Level 0] %s\n", vector)
				}
			}
		}

		// Level 1: Parent mappings
		for _, parentID := range cwe.Parents {
			parent, exists := hierarchy.CWEs[parentID]
			if !exists {
				continue
			}

			if len(parent.AttackVectors) > 0 {
				for _, vector := range parent.AttackVectors {
					if !candidates[vector] {
						candidates[vector] = true
						if verbose {
							fmt.Printf("    [Level 1 - CWE-%s] %s\n", parentID, vector)
						}
					}
				}
			}

			// Level 2: Grandparent mappings
			for _, grandparentID := range parent.Parents {
				grandparent, exists := hierarchy.CWEs[grandparentID]
				if !exists {
					continue
				}

				if len(grandparent.AttackVectors) > 0 {
					for _, vector := range grandparent.AttackVectors {
						if !candidates[vector] {
							candidates[vector] = true
							if verbose {
								fmt.Printf("    [Level 2 - CWE-%s] %s\n", grandparentID, vector)
							}
						}
					}
				}
			}
		}
	}

	if verbose {
		fmt.Printf("\nTotal candidate attack vectors: %d\n", len(candidates))
	}

	return candidates
}

func classifyNaiveBayes(description string, model *AttackVectorModel, candidates map[string]bool) []ClassificationResult {
	// Tokenize description
	tokens := tokenize(description)

	// Calculate log probabilities for each vector
	scores := make(map[string]float64)

	for vector := range model.VectorPriors {
		// Skip if not in candidates (if candidates are specified)
		if candidates != nil && len(candidates) > 0 && !candidates[vector] {
			continue
		}

		// Start with prior (log probability)
		logProb := math.Log(model.VectorPriors[vector])

		// Add word probabilities
		for _, word := range tokens {
			if prob, exists := model.WordGivenVector[vector][word]; exists {
				logProb += math.Log(prob)
			}
		}

		scores[vector] = logProb
	}

	// Convert to probabilities and sort
	results := make([]ClassificationResult, 0, len(scores))

	// Find max log prob for normalization
	maxLogProb := math.Inf(-1)
	for _, logProb := range scores {
		if logProb > maxLogProb {
			maxLogProb = logProb
		}
	}

	// Convert to probabilities
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
			Name:        getVectorName(vector),
			Probability: normalizedProb,
			Confidence:  confidence,
		})
	}

	// Sort by probability (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	return results
}

func getVectorName(vector string) string {
	vectorNames := map[string]string{
		"xss":                  "Cross-Site Scripting",
		"sql_injection":        "SQL Injection",
		"rce":                  "Remote Code Execution",
		"command_injection":    "OS Command Injection",
		"path_traversal":       "Path Traversal",
		"ssrf":                 "Server-Side Request Forgery",
		"deserialization":      "Deserialization Vulnerabilities",
		"auth_bypass":          "Authentication Bypass",
		"authz_bypass":         "Authorization Bypass",
		"file_upload":          "File Upload Vulnerabilities",
		"csrf":                 "Cross-Site Request Forgery",
		"xxe":                  "XML External Entity",
		"ldap_injection":       "LDAP Injection",
		"jndi_injection":       "JNDI/Expression Language Injection",
		"privilege_escalation": "Privilege Escalation",
		"buffer_overflow":      "Buffer Overflow",
		"idor":                 "Insecure Direct Object Reference",
		"http_desync":          "HTTP Request Smuggling",
		"hardcoded_creds":      "Hard-coded Credentials",
		"info_disclosure":      "Information Disclosure",
		"dos":                  "Denial of Service",
		"nosql_injection":      "NoSQL Injection",
		"xpath_injection":      "XPath Injection",
		"open_redirect":        "Open Redirect",
		"session_fixation":     "Session Fixation",
		"crypto_failure":       "Cryptographic Failures",
		"integer_overflow":     "Integer Overflow",
		"use_after_free":       "Use After Free",
		"null_pointer":         "NULL Pointer Dereference",
		"format_string":        "Format String Vulnerability",
		"email_injection":      "Email Header Injection",
		"race_condition":       "Race Condition",
		"ssti":                 "Server-Side Template Injection",
		"input_validation":     "Improper Input Validation",
		"code_injection":       "Code Injection",
	}

	if name, exists := vectorNames[vector]; exists {
		return name
	}
	return vector // Return ID if no mapping found
}

func tokenize(text string) []string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove version numbers
	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")

	// Remove CVE IDs
	cveRegex := regexp.MustCompile(`\bcve-\d{4}-\d+\b`)
	text = cveRegex.ReplaceAllString(text, "")

	// Extract words
	wordRegex := regexp.MustCompile(`[a-z]{3,}`)
	words := wordRegex.FindAllString(text, -1)

	// Filter stopwords (comprehensive list matching trainer)
	stopwords := map[string]bool{
		// Common English stopwords
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"that": true, "this": true, "are": true, "was": true, "were": true,
		"been": true, "being": true, "have": true, "has": true, "had": true,
		"but": true, "not": true, "can": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true,
		"shall": true, "into": true, "through": true, "during": true, "before": true,
		"after": true, "above": true, "below": true, "between": true, "under": true,
		"again": true, "further": true, "then": true, "once": true, "here": true,
		"there": true, "when": true, "where": true, "why": true, "how": true,
		"all": true, "both": true, "each": true, "few": true, "more": true,
		"most": true, "other": true, "some": true, "such": true, "only": true,
		"own": true, "same": true, "than": true, "too": true, "very": true,
		"just": true, "also": true, "any": true, "these": true, "those": true,
		"what": true, "which": true, "who": true, "whom": true, "whose": true,
		"out": true, "off": true, "over": true, "down": true, "does": true,
		"did": true, "doing": true, "nor": true, "about": true, "against": true,
		"because": true, "until": true, "while": true, "upon": true, "within": true,

		// Security-specific generic terms
		"vulnerability": true, "vulnerabilities": true, "vulnerable": true,
		"issue": true, "issues": true, "flaw": true, "flaws": true,
		"product": true, "products": true, "component": true, "components": true,
		"application": true, "applications": true, "software": true,
		"version": true, "versions": true, "release": true, "releases": true,
		"fix": true, "fixed": true, "resolved": true, "patch": true, "patched": true,
		"attacker": true, "attackers": true, "user": true, "users": true,
		"access": true, "system": true, "systems": true,
		"data": true, "code": true, "file": true, "files": true,
		"found": true, "used": true, "use": true, "uses": true, "using": true,
		"allows": true, "allow": true, "via": true,
		"perform": true, "execute": true, "run": true, "process": true,
		"obtain": true, "gain": true, "achieve": true, "lead": true, "leads": true,
		"function": true, "functions": true, "method": true, "methods": true,
		"value": true, "values": true, "parameter": true, "parameters": true,
		"request": true, "requests": true, "response": true, "responses": true,
		"certain": true, "specific": true, "particular": true, "multiple": true,
		"various": true, "related": true, "associated": true, "affected": true,
		"improper": true, "insufficient": true, "incorrect": true, "invalid": true,
		"due": true, "lack": true, "missing": true, "without": true,
		"cause": true, "causes": true, "caused": true, "result": true, "results": true,
		"resulting": true, "leading": true, "enable": true, "enabled": true,
		"make": true, "makes": true, "made": true, "making": true,
		"contain": true, "contains": true, "containing": true, "included": true,
		"including": true, "present": true, "exists": true, "existing": true,
	}

	filtered := make([]string, 0, len(words))
	for _, word := range words {
		if !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

func loadCWEHierarchy(filename string) (*CWEHierarchy, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var hierarchy CWEHierarchy
	if err := json.Unmarshal(data, &hierarchy); err != nil {
		return nil, err
	}

	return &hierarchy, nil
}

func loadNaiveBayesModel(filename string) (*AttackVectorModel, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var model AttackVectorModel
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, err
	}

	return &model, nil
}

// Load CAPEC data from JSON file
func loadCAPECData(filename string) ([]CAPECData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var capecs []CAPECData
	if err := json.Unmarshal(data, &capecs); err != nil {
		return nil, err
	}

	return capecs, nil
}

// Load CWE to CAPEC relationships
func loadRelationships(filename string) (*RelationshipsDB, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var rels RelationshipsDB
	if err := json.Unmarshal(data, &rels); err != nil {
		return nil, err
	}

	return &rels, nil
}

// Get candidate CAPECs from best CWEs
func getCandidateCAPECsFromCWEs(cweIDs []string, relationships *RelationshipsDB, verbose bool) map[string]bool {
	candidates := make(map[string]bool)

	if verbose {
		fmt.Printf("\nGetting candidate CAPECs from %d best CWEs...\n", len(cweIDs))
	}

	for _, cweID := range cweIDs {
		cweKey := "CWE-" + cweID
		if capecs, exists := relationships.CWEToCapec[cweKey]; exists {
			for _, capecID := range capecs {
				candidates[capecID] = true
			}
			if verbose {
				fmt.Printf("  %s → %d CAPECs\n", cweKey, len(capecs))
			}
		}
	}

	if verbose {
		fmt.Printf("Total candidate CAPECs: %d\n", len(candidates))
	}

	return candidates
}

// Classify CAPECs using Naive Bayes (simple overlap scoring)
func classifyNaiveBayesCAPEC(description string, candidates []CAPECData) []CAPECResult {
	// Tokenize description
	tokens := tokenize(description)
	descSet := make(map[string]bool)
	for _, token := range tokens {
		descSet[token] = true
	}

	// Calculate scores for each candidate CAPEC
	var results []CAPECResult

	for _, capec := range candidates {
		// Tokenize CAPEC description and name
		capecText := capec.Description + " " + capec.Name
		capecTokens := tokenize(capecText)

		// Calculate overlap
		overlap := 0
		capecSet := make(map[string]bool)
		for _, token := range capecTokens {
			capecSet[token] = true
			if descSet[token] {
				overlap++
			}
		}

		// Calculate probability (Jaccard similarity)
		union := len(descSet) + len(capecSet) - overlap
		probability := float64(overlap) / float64(union+1)

		// Boost if severity is high
		if capec.TypicalSeverity == "High" || capec.TypicalSeverity == "Very High" {
			probability *= 1.2
		}

		// Determine confidence
		confidence := "low"
		if probability > 0.15 {
			confidence = "high"
		} else if probability > 0.08 {
			confidence = "medium"
		}

		results = append(results, CAPECResult{
			CAPECID:     capec.CAPECID,
			Name:        capec.Name,
			Probability: probability,
			Confidence:  confidence,
		})
	}

	// Sort by probability (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	return results
}

// Rank CAPECs based on best CWEs
func rankCAPECs(description string, bestCWEs []string, capecData []CAPECData, relationships *RelationshipsDB, topN int, verbose bool) []CAPECResult {
	// Step 1: Get candidate CAPECs from best CWEs only
	candidateCAPECs := getCandidateCAPECsFromCWEs(bestCWEs, relationships, verbose)

	if len(candidateCAPECs) == 0 {
		if verbose {
			fmt.Println("No CAPECs found for the given CWEs")
		}
		return []CAPECResult{}
	}

	// Step 2: Filter CAPEC data to candidates only
	var candidates []CAPECData
	for _, capec := range capecData {
		if candidateCAPECs[capec.CAPECID] {
			candidates = append(candidates, capec)
		}
	}

	if verbose {
		fmt.Printf("Ranking %d candidate CAPECs...\n", len(candidates))
	}

	// Step 3: Rank using Naive Bayes
	results := classifyNaiveBayesCAPEC(description, candidates)

	// Step 4: Take top N
	if len(results) > topN {
		results = results[:topN]
	}

	return results
}
