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
	Pattern     string  `json:"pattern"`
	Specificity float64 `json:"specificity"`
	Boost       float64 `json:"boost"`
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

// Global resources
var (
	cweHierarchy    *CWEHierarchy
	nbModel         *AttackVectorModel
	patternTaxonomy *PatternTaxonomy
	resourcesPath   = "cwecapec/resources"
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
	outputPath := resourcesPath + "/training_data_reclassified.json"
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

				// Classify using hybrid approach
				vectors := classifyHybrid(entry.Description, entry.CWEs)

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

func classifyHybrid(description string, cweIDs []string) []string {
	// Layer 1: CWE Hierarchy lookup
	hierarchyVectors := classifyByCWEHierarchy(cweIDs)

	// Layer 2: Naive Bayes classification
	nbResults := classifyByNaiveBayes(description)

	// Layer 3: Pattern matching
	patternResults := classifyByPatterns(description)

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
		return scored[i].score > scored[j].score
	})

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
		score := 0.0

		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				continue
			}

			if re.MatchString(descLower) {
				score += pattern.Specificity * pattern.Boost
			}
		}

		if score > 0 {
			vectorScores[vector] = score
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
