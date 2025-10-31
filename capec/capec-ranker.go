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

// Ranked CAPEC result
type RankedCAPEC struct {
	CAPECID      string   `json:"capec_id"`
	Name         string   `json:"name"`
	Score        float64  `json:"score"`
	Confidence   string   `json:"confidence"`
	Severity     string   `json:"severity"`
	Likelihood   string   `json:"likelihood"`
	MatchedTerms []string `json:"matched_terms"`
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

// CWE to CAPEC mapping (comprehensive)
var cweToCapec = map[string][]string{
	// XSS family
	"79": {"588", "591", "592", "63", "85", "209"},
	"80": {"63", "588"},
	"81": {"63"},
	"82": {"63"},
	"83": {"83"}, // XPath Injection
	"84": {"63"},
	"85": {"63"},
	"86": {"63"},
	"87": {"63"},

	// SQL Injection family
	"89":  {"66", "7", "108"},
	"564": {"66"},

	// Command Injection family
	"77": {"88", "248", "15"},
	"78": {"88", "248", "15"},
	"88": {"88"},

	// Path Traversal family
	"22": {"126", "597"},
	"23": {"126"},
	"36": {"597"},
	"73": {"126"},

	// Buffer Overflow family
	"119": {"92", "100", "10"},
	"120": {"92"},
	"121": {"92"},
	"122": {"100"},
	"123": {"92"},
	"124": {"92"},
	"125": {"92"},
	"787": {"92", "100"},

	// Deserialization
	"502": {"586"},

	// XXE
	"611": {"221"},

	// SSRF
	"918": {"664"},

	// CSRF
	"352": {"62"},

	// Authentication
	"287": {"114", "115", "593"},
	"288": {"114"},
	"289": {"115"},
	"290": {"593"},

	// Authorization
	"285": {"69", "470"},
	"862": {"69"},
	"863": {"470"},

	// Code Injection
	"94": {"242", "35"},
	"95": {"242"},
	"96": {"242"},
	"97": {"242"},

	// LDAP Injection
	"90": {"136"},

	// XML Injection
	"91":  {"250"},
	"652": {"250"},
}

func main() {
	cveID := flag.String("cve", "", "CVE ID to analyze")
	dataFile := flag.String("data", "capec_training_data.json", "CAPEC data file")
	topN := flag.Int("top", 5, "Number of top results to show")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *cveID == "" {
		fmt.Println("Usage: capec-ranker-complete -cve CVE-ID [-data capec_training_data.json] [-top N] [-v]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("================================================================================")
	fmt.Println("CAPEC RANKER - Complete End-to-End Analysis")
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

	if len(candidateIDs) == 0 {
		fmt.Println("\n⚠ No candidate CAPECs found from CWE relationships")
		os.Exit(0)
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

	// Step 5: Rank CAPECs
	fmt.Printf("\n[STEP 3] Ranking CAPECs using TF-IDF similarity...\n")
	candidates := filterCandidates(allCAPECs, candidateIDs)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No matching CAPEC data found\n")
		os.Exit(1)
	}

	ranked := rankCAPECs(description, candidates, *verbose)

	// Step 6: Display ranked results
	fmt.Println("\n================================================================================")
	fmt.Println("[RANKED CAPECs] (Top", min(*topN, len(ranked)), ")")
	fmt.Println("================================================================================\n")

	displayCount := min(*topN, len(ranked))
	for i := 0; i < displayCount; i++ {
		result := ranked[i]
		fmt.Printf("%d. CAPEC-%s: %s\n", i+1, result.CAPECID, result.Name)
		fmt.Printf("   Similarity Score: %.4f (%s confidence)\n", result.Score, result.Confidence)
		if result.Severity != "" {
			fmt.Printf("   Severity: %s", result.Severity)
			if result.Likelihood != "" {
				fmt.Printf(" | Likelihood: %s", result.Likelihood)
			}
			fmt.Println()
		}
		if *verbose && len(result.MatchedTerms) > 0 {
			fmt.Printf("   Matched Terms: %v\n", result.MatchedTerms[:min(5, len(result.MatchedTerms))])
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
		fmt.Printf("Similarity Score: %.4f (%s confidence)\n", selected.Score, selected.Confidence)
		if selected.Severity != "" {
			fmt.Printf("Severity: %s", selected.Severity)
			if selected.Likelihood != "" {
				fmt.Printf(" | Likelihood: %s", selected.Likelihood)
			}
			fmt.Println()
		}
		if len(selected.MatchedTerms) > 0 {
			fmt.Printf("Matched Terms: %v\n", selected.MatchedTerms[:min(10, len(selected.MatchedTerms))])
		}
	}

	fmt.Println("\n================================================================================")
}

func fetchCVEData(cveID string) (string, []string, error) {
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
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Parse response
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

	// Extract English description
	var description string
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}

	// Extract CWE IDs
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
			for _, capecID := range capecs {
				capecSet[capecID] = true
			}
		}
	}

	// Convert to slice
	var candidates []string
	for capecID := range capecSet {
		candidates = append(candidates, capecID)
	}

	// Sort for consistent output
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

	// Convert to map for easy lookup
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

func rankCAPECs(cveDesc string, candidates []CAPECData, verbose bool) []RankedCAPEC {
	// Tokenize CVE description
	cveTokens := tokenize(cveDesc)
	cveTermFreq := calculateTermFrequency(cveTokens)

	// Calculate document frequency across all candidates
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

	// Calculate TF-IDF for CVE
	cveTFIDF := calculateTFIDF(cveTermFreq, docFreq, len(candidates))

	// Calculate similarity for each candidate
	var results []RankedCAPEC

	for _, capec := range candidates {
		capecText := capec.Description + " " + capec.Name + " " + strings.Join(capec.Prerequisites, " ")
		capecTokens := tokenize(capecText)
		capecTermFreq := calculateTermFrequency(capecTokens)
		capecTFIDF := calculateTFIDF(capecTermFreq, docFreq, len(candidates))

		// Calculate cosine similarity
		similarity := cosineSimilarity(cveTFIDF, capecTFIDF)

		// Find matched terms
		matchedTerms := findMatchedTerms(cveTokens, capecTokens)

		// Determine confidence
		confidence := "low"
		if similarity >= 0.3 {
			confidence = "high"
		} else if similarity >= 0.15 {
			confidence = "medium"
		}

		results = append(results, RankedCAPEC{
			CAPECID:      capec.CAPECID,
			Name:         capec.Name,
			Score:        similarity,
			Confidence:   confidence,
			Severity:     capec.TypicalSeverity,
			Likelihood:   capec.LikelihoodOfAttack,
			MatchedTerms: matchedTerms,
		})
	}

	// Sort by score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

func tokenize(text string) []string {
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
			df = 1 // Avoid division by zero
		}
		idf := math.Log(float64(totalDocs) / float64(df))
		tfidf[term] = tf * idf
	}

	return tfidf
}

func cosineSimilarity(vec1, vec2 map[string]float64) float64 {
	// Calculate dot product
	dotProduct := 0.0
	for term, val1 := range vec1 {
		if val2, exists := vec2[term]; exists {
			dotProduct += val1 * val2
		}
	}

	// Calculate magnitudes
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

	// Avoid division by zero
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
