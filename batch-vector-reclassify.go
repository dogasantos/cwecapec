package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Training data structures
type CVEEntry struct {
	CVEID         string   `json:"cve_id"`
	Description   string   `json:"description"`
	CWEs          []string `json:"cwes"`
	AttackVectors []string `json:"attack_vectors"`
	PublishedDate string   `json:"published_date"`
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
	CWEToVectorMapping  map[string][]string // Reverse mapping (built at runtime)
}

// Naive Bayes model structures
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

// Pattern taxonomy structures
type Pattern struct {
	Keywords    []string `json:"keywords"`
	Specificity float64  `json:"specificity"`
	Boost       float64  `json:"boost"`
	Support     int      `json:"support"`
}

type PatternTaxonomy struct {
	Patterns map[string][]Pattern `json:"patterns"`
}

// Classification result
type ClassificationResult struct {
	Vector      string  `json:"vector"`
	Probability float64 `json:"probability"`
	Source      string  `json:"source"`
}

// ScoredCWE represents a CWE with its relevance score
type ScoredCWE struct {
	ID    string
	Score float64
}

// Global resources
var (
	cweHierarchy    *CWEHierarchy
	nbModel         *AttackVectorModel
	patternTaxonomy *PatternTaxonomy
	resourcesPath   = "/home/ubuntu/cwecapec/resources"
	debugMode       = true // Enable debug output for first 10 CVEs
	debugCount      = 0
	debugMutex      sync.Mutex
)

func main() {
	fmt.Println("=================================================================")
	fmt.Println("Batch Re-Classification Tool")
	fmt.Println("Re-classifies training data using Phase 4 hybrid classifier")
	fmt.Println("=================================================================\n")

	// Load resources
	fmt.Print("Loading CWE hierarchy... ")
	if err := loadCWEHierarchy(); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	fmt.Print("Loading Naive Bayes model... ")
	if err := loadNaiveBayesModel(); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	fmt.Print("Loading pattern taxonomy... ")
	if err := loadPatternTaxonomy(); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Load training data
	fmt.Print("Loading training data... ")
	trainingData, err := loadTrainingData()
	if err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ (%d CVEs loaded)\n\n", len(trainingData))

	// Re-classify all CVEs
	fmt.Println("Starting re-classification...")
	startTime := time.Now()

	reclassified := reclassifyBatch(trainingData)

	elapsed := time.Since(startTime)
	fmt.Printf("\nRe-classification complete in %v\n", elapsed)
	fmt.Printf("Average: %.2f CVEs/second\n\n", float64(len(trainingData))/elapsed.Seconds())

	// Save results
	outputPath := resourcesPath + "/training_data.json"
	fmt.Printf("Saving results to %s... ", outputPath)
	if err := saveTrainingData(reclassified, outputPath); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Generate statistics
	fmt.Println("\n=================================================================")
	fmt.Println("Re-classification Statistics")
	fmt.Println("=================================================================")
	generateStats(trainingData, reclassified)
}

func loadCWEHierarchy() error {
	file, err := os.Open(resourcesPath + "/cwe_hierarchy.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	cweHierarchy = &CWEHierarchy{}
	if err := json.Unmarshal(data, cweHierarchy); err != nil {
		return err
	}

	// Build reverse mapping (CWE ID -> Attack Vectors)
	cweHierarchy.CWEToVectorMapping = make(map[string][]string)
	for cweID, vectors := range cweHierarchy.AttackVectorMapping {
		cweHierarchy.CWEToVectorMapping[cweID] = vectors
	}

	return nil
}

func loadNaiveBayesModel() error {
	file, err := os.Open(resourcesPath + "/naive_bayes_model.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	nbModel = &AttackVectorModel{}
	return json.Unmarshal(data, nbModel)
}

func loadPatternTaxonomy() error {
	file, err := os.Open(resourcesPath + "/pattern_taxonomy.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	patternTaxonomy = &PatternTaxonomy{}
	return json.Unmarshal(data, patternTaxonomy)
}

func loadTrainingData() ([]CVEEntry, error) {
	file, err := os.Open(resourcesPath + "/training_data.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var entries []CVEEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}

	return entries, nil
}

func saveTrainingData(entries []CVEEntry, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}

func reclassifyBatch(entries []CVEEntry) []CVEEntry {
	results := make([]CVEEntry, len(entries))

	// Progress tracking
	total := len(entries)
	processed := 0
	var mu sync.Mutex

	// Process in parallel using worker pool
	numWorkers := 8
	jobs := make(chan int, total)
	var wg sync.WaitGroup

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				entry := entries[i]

				// --- MODIFIED LOGIC START ---

				// Step 1: Rank CWEs by relevance and select top 2
				rankedCWEs := rankCWEsByRelevance(entry.CWEs, entry.Description, cweHierarchy, 2)

				// Step 2: Classify using hybrid approach, but only with the top 2 CWEs
				vectors := classifyHybrid(entry.Description, rankedCWEs, entry.CVEID)

				// --- MODIFIED LOGIC END ---

				// Update attack vectors
				entry.AttackVectors = vectors
				results[i] = entry

				// Update progress
				mu.Lock()
				processed++
				if processed%1000 == 0 || processed == total {
					fmt.Printf("\rProgress: %d/%d (%.1f%%)", processed, total, float64(processed)*100/float64(total))
				}
				mu.Unlock()
			}
		}()
	}

	// Send jobs
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)

	// Wait for completion
	wg.Wait()

	return results
}

// --- CWE RANKING LOGIC (Copied from phase4-relationship.go) ---

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
	if cwe, exists := hierarchy.CWEs[cweID]; exists && len(cwe.AttackVectors) > 0 {
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
		word = strings.ToLower(word)
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

// --- HYBRID CLASSIFICATION LOGIC (Modified to use only the provided CWEs) ---

func classifyHybrid(description string, cweIDs []string, cveID string) []string {
	debugMutex.Lock()
	showDebug := debugMode && debugCount < 10
	if showDebug {
		debugCount++
	}
	debugMutex.Unlock()

	if showDebug {
		fmt.Printf("\n=== DEBUG: %s ===\n", cveID)
		fmt.Printf("Description: %s\n", description)
		fmt.Printf("CWEs: %v\n", cweIDs)
	}
	// Layer 1: CWE Hierarchy lookup (uses the Top 2 Ranked CWEs)
	hierarchyVectors := classifyByCWEHierarchy(cweIDs)
	if showDebug {
		fmt.Printf("\nLayer 1 - CWE Hierarchy: %v\n", hierarchyVectors)
	}

	// Layer 2: Naive Bayes classification
	nbResults := classifyByNaiveBayes(description)
	if showDebug {
		fmt.Printf("\nLayer 2 - Naive Bayes (top 5):\n")
		for i := 0; i < 5 && i < len(nbResults); i++ {
			fmt.Printf("  %s: %.4f\n", nbResults[i].Vector, nbResults[i].Probability)
		}
	}

	// Layer 3: Pattern matching
	patternResults := classifyByPatterns(description)
	if showDebug {
		fmt.Printf("\nLayer 3 - Pattern Matching (top 5):\n")
		for i := 0; i < 5 && i < len(patternResults); i++ {
			fmt.Printf("  %s: %.4f\n", patternResults[i].Vector, patternResults[i].Probability)
		}
	}

	// Combine results
	vectorScores := make(map[string]float64)

	// Add hierarchy results (highest weight)
	for _, v := range hierarchyVectors {
		vectorScores[v] += 3.0
	}

	// Add Naive Bayes results
	for _, result := range nbResults {
		vectorScores[result.Vector] += result.Probability * 2.0
	}

	// Add pattern results
	for _, result := range patternResults {
		vectorScores[result.Vector] += result.Probability * 1.5
	}

	// Get top vectors
	type scoredVector struct {
		vector string
		score  float64
	}

	var scored []scoredVector
	for v, s := range vectorScores {
		scored = append(scored, scoredVector{v, s})
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			// Tie-breaking: sort alphabetically for consistency
			return scored[i].vector < scored[j].vector
		}
		return scored[i].score > scored[j].score
	})

	if showDebug {
		fmt.Printf("\nCombined Scores (top 10):\n")
		for i := 0; i < 10 && i < len(scored); i++ {
			fmt.Printf("  %s: %.4f\n", scored[i].vector, scored[i].score)
		}
	}

	// Return top 3 unique vectors
	var result []string
	seen := make(map[string]bool)
	for _, sv := range scored {
		if !seen[sv.vector] && len(result) < 3 {
			result = append(result, sv.vector)
			seen[sv.vector] = true
		}
	}

	// If no vectors found, return "unknown"
	if len(result) == 0 {
		result = []string{"unknown"}
	}

	return result
}

func classifyByCWEHierarchy(cweIDs []string) []string {
	vectorSet := make(map[string]bool)

	for _, cweID := range cweIDs {
		// Direct mapping
		if vectors, exists := cweHierarchy.CWEToVectorMapping[cweID]; exists {
			for _, v := range vectors {
				vectorSet[v] = true
			}
		}

		// Parent mapping
		if cweInfo, exists := cweHierarchy.CWEs[cweID]; exists {
			for _, parentID := range cweInfo.Parents {
				if vectors, exists := cweHierarchy.CWEToVectorMapping[parentID]; exists {
					for _, v := range vectors {
						vectorSet[v] = true
					}
				}
			}
		}
	}

	var result []string
	for v := range vectorSet {
		result = append(result, v)
	}

	// Sort alphabetically for deterministic order
	sort.Strings(result)

	return result
}

func classifyByNaiveBayes(description string) []ClassificationResult {
	words := tokenize(description)
	scores := make(map[string]float64)

	for _, vector := range nbModel.AttackVectors {
		logProb := math.Log(nbModel.VectorPriors[vector])

		for _, word := range words {
			if prob, exists := nbModel.WordGivenVector[vector][word]; exists {
				logProb += math.Log(prob)
			}
		}

		scores[vector] = logProb
	}

	// Normalize to probabilities
	maxScore := -math.MaxFloat64
	for _, score := range scores {
		if score > maxScore {
			maxScore = score
		}
	}

	total := 0.0
	for vector := range scores {
		scores[vector] = math.Exp(scores[vector] - maxScore)
		total += scores[vector]
	}

	for vector := range scores {
		scores[vector] /= total
	}

	// Return top 3
	type scoredVector struct {
		vector string
		prob   float64
	}

	var sorted []scoredVector
	for v, p := range scores {
		sorted = append(sorted, scoredVector{v, p})
	}

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].prob == sorted[j].prob {
			// Tie-breaking: sort alphabetically for consistency
			return sorted[i].vector < sorted[j].vector
		}
		return sorted[i].prob > sorted[j].prob
	})

	var results []ClassificationResult
	for i := 0; i < 3 && i < len(sorted); i++ {
		results = append(results, ClassificationResult{
			Vector:      sorted[i].vector,
			Probability: sorted[i].prob,
			Source:      "naive_bayes",
		})
	}

	return results
}

func classifyByPatterns(description string) []ClassificationResult {
	descLower := strings.ToLower(description)
	vectorScores := make(map[string]float64)

	for vector, patterns := range patternTaxonomy.Patterns {
		totalBoost := 0.0

		for _, pattern := range patterns {
			// Check if all keywords in the pattern are present
			allMatch := true
			for _, keyword := range pattern.Keywords {
				if !strings.Contains(descLower, keyword) {
					allMatch = false
					break
				}
			}

			if allMatch {
				// Normalize boost (divide by 100 since all boosts are 100.0)
				// and weight by specificity
				totalBoost += (pattern.Boost / 100.0) * pattern.Specificity
			}
		}

		// Cap the maximum boost per vector to prevent overwhelming other layers
		if totalBoost > 5.0 {
			totalBoost = 5.0
		}

		if totalBoost > 0 {
			vectorScores[vector] = totalBoost
		}
	}

	// Sort by score
	type scoredVector struct {
		vector string
		score  float64
	}

	var sorted []scoredVector
	for v, s := range vectorScores {
		sorted = append(sorted, scoredVector{v, s})
	}

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].score == sorted[j].score {
			// Tie-breaking: sort alphabetically for consistency
			return sorted[i].vector < sorted[j].vector
		}
		return sorted[i].score > sorted[j].score
	})

	var results []ClassificationResult
	for i := 0; i < 3 && i < len(sorted); i++ {
		results = append(results, ClassificationResult{
			Vector:      sorted[i].vector,
			Probability: sorted[i].score,
			Source:      "pattern",
		})
	}

	return results
}

func tokenize(text string) []string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove special characters, keep only alphanumeric and spaces
	re := regexp.MustCompile(`[^a-z0-9\s]`)
	text = re.ReplaceAllString(text, " ")

	// Split on whitespace
	words := strings.Fields(text)

	// Remove stop words and short words
	stopWords := map[string]bool{
		"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
		"be": true, "by": true, "for": true, "from": true, "has": true, "he": true,
		"in": true, "is": true, "it": true, "its": true, "of": true, "on": true,
		"that": true, "the": true, "to": true, "was": true, "will": true, "with": true,
	}

	var filtered []string
	for _, word := range words {
		if len(word) > 2 && !stopWords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

func generateStats(original, reclassified []CVEEntry) {
	// Count changes
	changed := 0
	vectorChanges := make(map[string]int)

	for i := 0; i < len(original); i++ {
		origVectors := original[i].AttackVectors
		newVectors := reclassified[i].AttackVectors

		if !equalSlices(origVectors, newVectors) {
			changed++

			// Track which vectors were added/removed
			for _, v := range newVectors {
				if !contains(origVectors, v) {
					vectorChanges[v]++
				}
			}
		}
	}

	fmt.Printf("Total CVEs: %d\n", len(original))
	fmt.Printf("Changed: %d (%.1f%%)\n", changed, float64(changed)*100/float64(len(original)))
	fmt.Printf("Unchanged: %d (%.1f%%)\n\n", len(original)-changed, float64(len(original)-changed)*100/float64(len(original)))

	// Top vector changes
	type vectorChange struct {
		vector string
		count  int
	}

	var changes []vectorChange
	for v, c := range vectorChanges {
		changes = append(changes, vectorChange{v, c})
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].count > changes[j].count
	})

	fmt.Println("Top 10 newly added attack vectors:")
	for i := 0; i < 10 && i < len(changes); i++ {
		fmt.Printf("  %d. %s: %d CVEs\n", i+1, changes[i].vector, changes[i].count)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]bool)
	for _, v := range a {
		aMap[v] = true
	}

	for _, v := range b {
		if !aMap[v] {
			return false
		}
	}

	return true
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
