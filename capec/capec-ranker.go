package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
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

func main() {
	cveDesc := flag.String("cve-desc", "", "CVE description")
	capecIDs := flag.String("capec-ids", "", "Comma-separated CAPEC IDs to rank (e.g., 588,591,592,63)")
	dataFile := flag.String("data", "capec_training_data.json", "CAPEC data file")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *cveDesc == "" || *capecIDs == "" {
		fmt.Println("Usage: capec-ranker -cve-desc \"description\" -capec-ids \"588,591,592,63\" [-data capec_training_data.json] [-v]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("=================================================================")
	fmt.Println("CAPEC Ranker (TF-IDF Similarity)")
	fmt.Println("=================================================================")

	// Load CAPEC data
	if *verbose {
		fmt.Printf("\nLoading CAPEC data from %s...\n", *dataFile)
	}
	allCAPECs, err := loadCAPECData(*dataFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CAPEC data: %v\n", err)
		os.Exit(1)
	}

	// Parse candidate CAPEC IDs
	candidateIDs := strings.Split(*capecIDs, ",")
	for i := range candidateIDs {
		candidateIDs[i] = strings.TrimSpace(candidateIDs[i])
	}

	if *verbose {
		fmt.Printf("Loaded %d total CAPECs\n", len(allCAPECs))
		fmt.Printf("Ranking %d candidate CAPECs\n", len(candidateIDs))
	}

	// Filter to candidate CAPECs
	candidates := filterCandidates(allCAPECs, candidateIDs)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No matching CAPECs found for IDs: %v\n", candidateIDs)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("Found %d matching CAPECs\n", len(candidates))
	}

	// Rank using TF-IDF similarity
	fmt.Println("\nRanking CAPECs by similarity to CVE description...")
	ranked := rankCAPECs(*cveDesc, candidates, *verbose)

	// Display results
	fmt.Println("\n=================================================================")
	fmt.Println("Ranked CAPECs:")
	fmt.Println("=================================================================\n")

	for i, result := range ranked {
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
		if i < len(ranked)-1 {
			fmt.Println()
		}
	}
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
