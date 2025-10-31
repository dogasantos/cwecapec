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

// CAPEC training data structure
type CAPECData struct {
	CAPECID            string   `json:"capec_id"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	LikelihoodOfAttack string   `json:"likelihood_of_attack"`
	TypicalSeverity    string   `json:"typical_severity"`
	RelatedCWEs        []string `json:"related_cwes"`
	Prerequisites      []string `json:"prerequisites"`
}

// Ranked CAPEC result with hybrid scoring
type RankedCAPEC struct {
	CAPECID         string   `json:"capec_id"`
	Name            string   `json:"name"`
	TotalScore      float64  `json:"total_score"`
	TFIDFScore      float64  `json:"tfidf_score"`
	CWEScore        float64  `json:"cwe_score"`
	KeywordScore    float64  `json:"keyword_score"`
	MetadataScore   float64  `json:"metadata_score"`
	Confidence      string   `json:"confidence"`
	Severity        string   `json:"severity"`
	Likelihood      string   `json:"likelihood"`
	MatchedTerms    []string `json:"matched_terms"`
	MatchedKeywords []string `json:"matched_keywords"`
}

// NVD API structures
type NVDResponse struct {
	Vulnerabilities []struct {
		CVE CVEItem `json:"cve"`
	} `json:"vulnerabilities"`
}

type CVEItem struct {
	ID           string        `json:"id"`
	Descriptions []Description `json:"descriptions"`
	Weaknesses   []Weakness    `json:"weaknesses"`
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

// CWE to CAPEC mapping with relationship strength
type CWEMapping struct {
	CAPECs   []string
	Strength string // "direct", "parent", "related"
}

var cweToCapec = map[string][]string{
	// XSS family
	"79":  {"588", "591", "592", "63", "85", "209"},
	"80":  {"63", "588"},
	"917": {"242", "35"}, // JNDI/EL Injection
	"502": {"586"},       // Deserialization
	"89":  {"66", "7", "108"},
	"77":  {"88", "248", "15"},
	"78":  {"88", "248", "15"},
	"22":  {"126", "597"},
	"119": {"92", "100", "10"},
	"611": {"221"},
	"918": {"664"},
	"352": {"62"},
	"287": {"114", "115", "593"},
	"90":  {"136"},
	"400": {"130", "147"},      // Resource exhaustion
	"94":  {"242", "35", "77"}, // Code Injection
	"95":  {"35"},              // Improper Neutralization of Directives in Dynamically Evaluated Code
	"20":  {},                  // Improper input validation (generic)
}

// Attack pattern keywords for fallback matching
// CWE Specificity Weights
// High (1.5): Attack-specific CWEs (1-3 CAPECs)
// Medium (1.0): Category-specific CWEs (3-10 CAPECs)
// Low (0.5): Generic CWEs (10+ CAPECs)
var cweSpecificity = map[string]float64{
	// Highly Specific (1.5x)
	"502": 1.5, // Deserialization
	"611": 1.5, // XXE
	"918": 1.5, // SSRF
	"352": 1.5, // CSRF
	"434": 1.5, // File Upload
	"94":  1.5, // Code Injection
	"95":  1.5, // Eval Injection
	"798": 1.5, // Hard-coded Credentials

	// Moderately Specific (1.0x)
	"79":  1.0, // XSS
	"89":  1.0, // SQL Injection
	"77":  1.0, // Command Injection
	"78":  1.0, // OS Command Injection
	"22":  1.0, // Path Traversal
	"119": 1.0, // Buffer Overflow
	"120": 1.0, // Buffer Copy
	"125": 1.0, // Out-of-bounds Read
	"787": 1.0, // Out-of-bounds Write
	"190": 1.0, // Integer Overflow

	// Generic (0.5x)
	"20":  0.5, // Improper Input Validation
	"200": 0.5, // Information Disclosure
	"287": 0.5, // Authentication
	"269": 0.5, // Privilege Management
	"400": 0.5, // Resource Exhaustion
	"444": 0.5, // HTTP Request Smuggling
	"501": 0.5, // Trust Boundary
	"93":  0.5, // CRLF Injection
}

var attackKeywords = map[string][]string{
	"586": {"deserialization", "deserialize", "unserialize", "object injection", "serialized", "pickle", "jndi", "ldap", "rmi"},
	"588": {"dom", "dom-based", "client-side", "javascript", "document object"},
	"591": {"reflected", "non-persistent", "url parameter", "query string"},
	"592": {"stored", "persistent", "database", "save"},
	"63":  {"xss", "cross-site scripting", "script injection"},
	"66":  {"sql injection", "union select", "sql query"},
	"7":   {"blind sql", "time-based", "boolean"},
	"88":  {"command injection", "os command", "shell command", "exec"},
	"126": {"path traversal", "directory traversal", "../"},
	"221": {"xxe", "xml external entity"},
	"664": {"ssrf", "server-side request forgery"},
	"62":  {"csrf", "cross-site request forgery"},
	"242": {"code injection", "remote code execution", "rce", "arbitrary code"},
	"35":  {"executable code", "non-executable", "eval", "dynamic evaluation"},
	"77":  {"user-controlled", "variable manipulation", "parameter tampering"},
	"31":  {"cookie", "http cookie", "cookie manipulation", "cookie theft"},
	"102": {"session sidejacking", "session sniffing", "session interception", "hijack"},
	"196": {"session forging", "session falsification", "forge session", "fake session"},
	"226": {"session manipulation", "session takeover", "session hijacking", "credential manipulation"},
}

func main() {
	cveID := flag.String("cve", "", "CVE ID to analyze")
	dataFile := flag.String("data", "capec_training_data.json", "CAPEC data file")
	topN := flag.Int("top", 5, "Number of top results to show")
	verbose := flag.Bool("v", false, "Verbose output with score breakdown")
	flag.Parse()

	if *cveID == "" {
		fmt.Println("Usage: capec-ranker-hybrid -cve CVE-ID [-data capec_training_data.json] [-top N] [-v]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("================================================================================")
	fmt.Println("CAPEC RANKER - Hybrid Scoring (TF-IDF + CWE + Keywords + Metadata)")
	fmt.Println("================================================================================")

	// Step 1: Fetch CVE data
	fmt.Printf("\n[STEP 1] Fetching CVE data from NVD API...\n")
	description, cweIDs, err := fetchCVEData(*cveID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching CVE: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[CVE INFORMATION]\n")
	fmt.Printf("ID: %s\n", *cveID)
	fmt.Printf("Description: %s\n", description)

	// Step 2: Display CWEs
	fmt.Printf("\n[RELATED CWEs] (%d)\n", len(cweIDs))
	if len(cweIDs) == 0 {
		fmt.Println("  No CWEs found for this CVE")
	} else {
		for _, cweID := range cweIDs {
			fmt.Printf("  • CWE-%s\n", cweID)
		}
	}

	// Step 3: Get candidate CAPECs from CWEs
	fmt.Printf("\n[STEP 2] Getting candidate CAPECs from CWE relationships...\n")
	candidateIDs := getCandidateCAPECs(cweIDs)

	// Step 3.5: Fallback if no candidates found (e.g., generic CWE-20)
	if len(candidateIDs) == 0 {
		fmt.Println("\n⚠ No direct CWE-to-CAPEC mapping found")
		fmt.Println("[STEP 2.5] Using keyword-based fallback...\n")

		// Load CAPEC data first for fallback
		allCAPECs, err := loadCAPECData(*dataFile)
		if err != nil {
			fmt.Printf("Error loading CAPEC data: %v\n", err)
			os.Exit(1)
		}

		candidateIDs = getCandidateCAPECsFallback(description, allCAPECs)

		if len(candidateIDs) == 0 {
			fmt.Println("\n⚠ No candidate CAPECs found even with fallback")
			os.Exit(0)
		}

	}

	fmt.Printf("\n[CANDIDATE CAPECs] (%d)\n", len(candidateIDs))
	for i, capecID := range candidateIDs {
		fmt.Printf("  %d. CAPEC-%s\n", i+1, capecID)
	}

	// Step 4: Load CAPEC data
	if *verbose {
		fmt.Printf("\n[STEP 3] Loading CAPEC data from %s...\n", *dataFile)
	}
	allCAPECs, err := loadCAPECData(*dataFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CAPEC data: %v\n", err)
		os.Exit(1)
	}

	// Step 5: Rank CAPECs using hybrid scoring
	fmt.Printf("\n[STEP 3] Ranking CAPECs using hybrid scoring...\n")
	if *verbose {
		fmt.Println("  Scoring components:")
		fmt.Println("    • TF-IDF Similarity (0-40 points)")
		fmt.Println("    • CWE Relationship (0-30 points)")
		fmt.Println("    • Keyword Matching (0-20 points)")
		fmt.Println("    • Metadata (Severity/Likelihood) (0-10 points)")
	}

	candidates := filterCandidates(allCAPECs, candidateIDs)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No matching CAPEC data found\n")
		os.Exit(1)
	}

	ranked := rankCAPECsHybrid(description, cweIDs, candidates, *verbose)

	// Step 6: Display ranked results
	fmt.Println("\n================================================================================")
	fmt.Println("[RANKED CAPECs] (Top", min(*topN, len(ranked)), ")")
	fmt.Println("================================================================================\n")

	displayCount := min(*topN, len(ranked))
	for i := 0; i < displayCount; i++ {
		result := ranked[i]
		fmt.Printf("%d. CAPEC-%s: %s\n", i+1, result.CAPECID, result.Name)
		fmt.Printf("   Total Score: %.2f/100 (%s confidence)\n", result.TotalScore, result.Confidence)

		if *verbose {
			fmt.Printf("   Score Breakdown:\n")
			fmt.Printf("     - TF-IDF Similarity: %.2f/40\n", result.TFIDFScore)
			fmt.Printf("     - CWE Relationship: %.2f/30\n", result.CWEScore)
			fmt.Printf("     - Keyword Matching: %.2f/20\n", result.KeywordScore)
			fmt.Printf("     - Metadata: %.2f/10\n", result.MetadataScore)
		}

		if result.Severity != "" {
			fmt.Printf("   Severity: %s", result.Severity)
			if result.Likelihood != "" {
				fmt.Printf(" | Likelihood: %s", result.Likelihood)
			}
			fmt.Println()
		}

		if len(result.MatchedKeywords) > 0 {
			fmt.Printf("   Matched Keywords: %v\n", result.MatchedKeywords)
		}

		if i < displayCount-1 {
			fmt.Println()
		}
	}

	// Step 7: Highlight the selected CAPEC
	if len(ranked) > 0 {
		selected := ranked[0]
		fmt.Println("\n================================================================================")
		fmt.Println("[SELECTED CAPEC] (Highest Ranked)")
		fmt.Println("================================================================================\n")
		fmt.Printf("CAPEC-%s: %s\n", selected.CAPECID, selected.Name)
		fmt.Printf("Total Score: %.2f/100 (%s confidence)\n", selected.TotalScore, selected.Confidence)
		if *verbose {
			fmt.Printf("\nScore Breakdown:\n")
			fmt.Printf("  • TF-IDF Similarity: %.2f/40\n", selected.TFIDFScore)
			fmt.Printf("  • CWE Relationship: %.2f/30\n", selected.CWEScore)
			fmt.Printf("  • Keyword Matching: %.2f/20\n", selected.KeywordScore)
			fmt.Printf("  • Metadata: %.2f/10\n", selected.MetadataScore)
		}
		if selected.Severity != "" {
			fmt.Printf("Severity: %s", selected.Severity)
			if selected.Likelihood != "" {
				fmt.Printf(" | Likelihood: %s", selected.Likelihood)
			}
			fmt.Println()
		}
		if len(selected.MatchedKeywords) > 0 {
			fmt.Printf("Matched Keywords: %v\n", selected.MatchedKeywords)
		}
	}

	fmt.Println("\n================================================================================")
}

func rankCAPECsHybrid(cveDesc string, cweIDs []string, candidates []CAPECData, verbose bool) []RankedCAPEC {
	cveDescLower := strings.ToLower(cveDesc)

	// Tokenize CVE description for TF-IDF
	cveTokens := tokenize(cveDesc)
	cveTermFreq := calculateTermFrequency(cveTokens)

	// Calculate document frequency for TF-IDF
	docFreq := make(map[string]int)
	for _, capec := range candidates {
		capecText := capec.Description + " " + capec.Name + " " + strings.Join(capec.Prerequisites, " ")
		capecTokens := tokenize(capecText)
		uniqueTerms := make(map[string]bool)
		for _, term := range capecTokens {
			uniqueTerms[term] = true
		}
		for term := range uniqueTerms {
			docFreq[term]++
		}
	}

	cveTFIDF := calculateTFIDF(cveTermFreq, docFreq, len(candidates))

	var results []RankedCAPEC

	for _, capec := range candidates {
		// Component 1: TF-IDF Similarity (0-40 points)
		capecText := capec.Description + " " + capec.Name + " " + strings.Join(capec.Prerequisites, " ")
		capecTokens := tokenize(capecText)
		capecTermFreq := calculateTermFrequency(capecTokens)
		capecTFIDF := calculateTFIDF(capecTermFreq, docFreq, len(candidates))

		tfidfSimilarity := cosineSimilarity(cveTFIDF, capecTFIDF)
		tfidfScore := tfidfSimilarity * 40.0 // Scale to 0-40

		// Component 2: CWE Relationship Strength (0-30 points)
		cweScore := calculateCWEScore(capec, cweIDs)

		// Component 3: Keyword Matching (0-20 points)
		keywordScore, matchedKeywords := calculateKeywordScore(cveDescLower, capec.CAPECID)

		// Component 4: Metadata Score (0-10 points)
		metadataScore := calculateMetadataScore(capec)

		// Total Score
		totalScore := tfidfScore + cweScore + keywordScore + metadataScore

		// Single candidate boost (if only 1 CAPEC, ensure reasonable score)
		if len(candidates) == 1 && totalScore < 50 {
			totalScore = 50.0 // Minimum score for single candidate
		}

		// Determine confidence
		confidence := "low"
		if totalScore >= 70 {
			confidence = "high"
		} else if totalScore >= 50 {
			confidence = "medium"
		}

		// Find matched terms for display
		matchedTerms := findMatchedTerms(cveTokens, capecTokens)

		results = append(results, RankedCAPEC{
			CAPECID:         capec.CAPECID,
			Name:            capec.Name,
			TotalScore:      totalScore,
			TFIDFScore:      tfidfScore,
			CWEScore:        cweScore,
			KeywordScore:    keywordScore,
			MetadataScore:   metadataScore,
			Confidence:      confidence,
			Severity:        capec.TypicalSeverity,
			Likelihood:      capec.LikelihoodOfAttack,
			MatchedTerms:    matchedTerms,
			MatchedKeywords: matchedKeywords,
		})
	}

	// Sort by total score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].TotalScore > results[j].TotalScore
	})

	return results
}

func calculateCWEScore(capec CAPECData, cveWEs []string) float64 {
	// Base scores:
	// - Direct CWE match: 30 points × specificity weight
	// - Related CWE match: 15 points × specificity weight

	maxScore := 0.0

	for _, cweID := range cveWEs {
		for _, relatedCWE := range capec.RelatedCWEs {
			if relatedCWE == cweID {
				// Direct match - apply specificity weight
				specificity := getCWESpecificity(cweID)
				score := 30.0 * specificity
				if score > maxScore {
					maxScore = score
				}
			}
		}
	}

	// If no direct match, give partial credit
	if maxScore == 0 {
		maxScore = 15.0
	}

	return maxScore
}

func getCWESpecificity(cweID string) float64 {
	if weight, exists := cweSpecificity[cweID]; exists {
		return weight
	}
	// Default to medium specificity if not in map
	return 1.0
}

func calculateKeywordScore(cveDesc string, capecID string) (float64, []string) {
	keywords, exists := attackKeywords[capecID]
	if !exists {
		return 0.0, []string{}
	}

	var matched []string
	totalScore := 0.0

	for _, keyword := range keywords {
		if strings.Contains(cveDesc, keyword) {
			matched = append(matched, keyword)

			// Weight by keyword specificity (longer = more specific)
			wordCount := len(strings.Fields(keyword))
			if wordCount >= 3 {
				totalScore += 8.0 // Multi-word phrase (e.g., "session takeover")
			} else if wordCount == 2 {
				totalScore += 5.0 // Two-word phrase
			} else {
				totalScore += 3.0 // Single word
			}
		}
	}

	// Cap at 20 points
	if totalScore > 20.0 {
		totalScore = 20.0
	}

	return totalScore, matched
}

func calculateMetadataScore(capec CAPECData) float64 {
	score := 0.0

	// Severity scoring
	switch strings.ToLower(capec.TypicalSeverity) {
	case "very high":
		score += 6.0
	case "high":
		score += 5.0
	case "medium":
		score += 3.0
	case "low":
		score += 1.0
	}

	// Likelihood scoring
	switch strings.ToLower(capec.LikelihoodOfAttack) {
	case "high":
		score += 4.0
	case "medium":
		score += 2.0
	case "low":
		score += 1.0
	}

	return score
}

// ... (rest of the helper functions remain the same: fetchCVEData, getCandidateCAPECs, loadCAPECData, etc.)

func fetchCVEData(cveID string) (string, []string, error) {
	cveID = strings.ToUpper(cveID)
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return "", nil, err
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return "", nil, fmt.Errorf("CVE not found")
	}

	cve := nvdResp.Vulnerabilities[0].CVE

	var description string
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}

	var cweIDs []string
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			if strings.HasPrefix(desc.Value, "CWE-") {
				cweID := strings.TrimPrefix(desc.Value, "CWE-")
				cweIDs = append(cweIDs, cweID)
			}
		}
	}

	return description, cweIDs, nil
}

func getCandidateCAPECs(cweIDs []string) []string {
	capecSet := make(map[string]bool)

	for _, cweID := range cweIDs {
		if capecs, exists := cweToCapec[cweID]; exists {
			if len(capecs) > 0 {
				// CWE has specific mappings
				for _, capecID := range capecs {
					capecSet[capecID] = true
				}
			}
			// If empty list (generic CWE like CWE-20), skip for now
			// Fallback will be handled in main()
		}
	}

	var candidates []string
	for capecID := range capecSet {
		candidates = append(candidates, capecID)
	}

	sort.Strings(candidates)
	return candidates
}

// Fallback: get CAPECs from CAPEC data based on keywords when CWE mapping is empty
func getCandidateCAPECsFallback(cveDesc string, allCAPECs map[string]CAPECData) []string {
	cveDescLower := strings.ToLower(cveDesc)

	// Define keyword-to-CAPEC patterns for common attack types
	keywordPatterns := map[string][]string{
		"session": {"31", "102", "196", "226"},      // Session attacks
		"cookie":  {"31", "102"},                    // Cookie manipulation
		"xss":     {"63", "588", "591", "592"},      // XSS variants
		"sql":     {"7", "66", "108", "109", "110"}, // SQL injection
		"command": {"88"},                           // Command injection
		"buffer":  {"8", "9", "10", "14", "24"},     // Buffer overflow
		"ldap":    {"136"},                          // LDAP injection
		"xpath":   {"83"},                           // XPath injection
		"xml":     {"250"},                          // XML injection
	}

	capecSet := make(map[string]bool)

	// Match keywords in CVE description
	for keyword, capecs := range keywordPatterns {
		if strings.Contains(cveDescLower, keyword) {
			for _, capecID := range capecs {
				// Only add if CAPEC exists in data
				if _, exists := allCAPECs[capecID]; exists {
					capecSet[capecID] = true
				}
			}
		}
	}

	var candidates []string
	for capecID := range capecSet {
		candidates = append(candidates, capecID)
	}

	sort.Strings(candidates)
	return candidates
}

func loadCAPECData(filename string) (map[string]CAPECData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var dataList []CAPECData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&dataList); err != nil {
		return nil, err
	}

	dataMap := make(map[string]CAPECData)
	for _, capec := range dataList {
		dataMap[capec.CAPECID] = capec
	}

	return dataMap, nil
}

func filterCandidates(allCAPECs map[string]CAPECData, candidateIDs []string) []CAPECData {
	var candidates []CAPECData

	for _, id := range candidateIDs {
		if capec, exists := allCAPECs[id]; exists {
			candidates = append(candidates, capec)
		}
	}

	return candidates
}

func tokenize(text string) []string {
	text = strings.ToLower(text)

	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")
	cveRegex := regexp.MustCompile(`\bcve-\d{4}-\d+\b`)
	text = cveRegex.ReplaceAllString(text, "")

	wordRegex := regexp.MustCompile(`[a-z]{3,}`)
	words := wordRegex.FindAllString(text, -1)

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

func calculateTermFrequency(tokens []string) map[string]float64 {
	freq := make(map[string]int)
	for _, token := range tokens {
		freq[token]++
	}

	tf := make(map[string]float64)
	maxFreq := 0
	for _, count := range freq {
		if count > maxFreq {
			maxFreq = count
		}
	}

	if maxFreq == 0 {
		return tf
	}

	for term, count := range freq {
		tf[term] = float64(count) / float64(maxFreq)
	}

	return tf
}

func calculateTFIDF(termFreq map[string]float64, docFreq map[string]int, totalDocs int) map[string]float64 {
	tfidf := make(map[string]float64)

	for term, tf := range termFreq {
		df := docFreq[term]
		if df == 0 {
			df = 1
		}
		idf := math.Log(float64(totalDocs) / float64(df))
		tfidf[term] = tf * idf
	}

	return tfidf
}

func cosineSimilarity(vec1, vec2 map[string]float64) float64 {
	dotProduct := 0.0
	for term, val1 := range vec1 {
		if val2, exists := vec2[term]; exists {
			dotProduct += val1 * val2
		}
	}

	mag1 := 0.0
	for _, val := range vec1 {
		mag1 += val * val
	}
	mag1 = math.Sqrt(mag1)

	mag2 := 0.0
	for _, val := range vec2 {
		mag2 += val * val
	}
	mag2 = math.Sqrt(mag2)

	if mag1 == 0 || mag2 == 0 {
		return 0.0
	}

	return dotProduct / (mag1 * mag2)
}

func findMatchedTerms(tokens1, tokens2 []string) []string {
	set1 := make(map[string]bool)
	for _, token := range tokens1 {
		set1[token] = true
	}

	set2 := make(map[string]bool)
	for _, token := range tokens2 {
		set2[token] = true
	}

	var matched []string
	for term := range set1 {
		if set2[term] {
			matched = append(matched, term)
		}
	}

	return matched
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
