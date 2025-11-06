package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
)

// -------------------- Data Structures --------------------

type CVETrainingExample struct {
	CVEID         string   `json:"cve_id"`
	Description   string   `json:"description"`
	CWEIDs        []string `json:"cwes"`
	AttackVectors []string `json:"attack_vectors"`
}

type PatternRule struct {
	Keywords    []string `json:"keywords"`
	Specificity float64  `json:"specificity"`
	Boost       float64  `json:"boost"`
	Support     int      `json:"support"` // Number of CVEs this pattern appears in
}

type PatternTaxonomy struct {
	Patterns map[string][]PatternRule `json:"patterns"` // attack_vector -> rules
	Stats    TaxonomyStats            `json:"stats"`
}

type TaxonomyStats struct {
	TotalVectors  int                      `json:"total_vectors"`
	TotalPatterns int                      `json:"total_patterns"`
	VectorCounts  map[string]int           `json:"vector_counts"`
	TopPatterns   map[string][]PatternRule `json:"top_patterns_per_vector"`
}

type TermScore struct {
	Term        string
	TF          float64 // Term frequency in this vector
	IDF         float64 // Inverse document frequency
	TFIDF       float64 // TF-IDF score
	Specificity float64 // How specific to this vector (0-1)
	Support     int     // Number of CVEs containing this term
}

// -------------------- Configuration --------------------

const (
	TrainingDataPath    = "resources/training_data.json"
	PatternTaxonomyPath = "resources/pattern_taxonomy.json"

	MinTermFrequency     = 3   // Term must appear at least 3 times in a vector
	MinSpecificity       = 0.6 // Term must be at least 60% specific to the vector
	MaxPatternsPerVector = 15  // Keep top 15 patterns per vector
	MinPatternLength     = 3   // Minimum keyword length
)

// -------------------- Main Function --------------------

func main() {
	fmt.Println("Generating Attack Vector Pattern Taxonomy from Training Data")
	fmt.Println(strings.Repeat("=", 70))

	// Step 1: Load training data
	fmt.Println("\n[1/4] Loading CVE training data...")
	trainingData, err := loadTrainingData(TrainingDataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading training data: %v\n", err)
		fmt.Println("Run phase1-collector first to generate training data")
		os.Exit(1)
	}
	fmt.Printf("  Loaded %d CVE examples\n", len(trainingData))

	// Step 2: Extract discriminative terms per attack vector
	fmt.Println("\n[2/4] Extracting discriminative terms per attack vector...")
	taxonomy := buildPatternTaxonomy(trainingData)
	fmt.Printf("  Generated patterns for %d attack vectors\n", len(taxonomy.Patterns))

	// Step 3: Calculate specificity and boost scores
	fmt.Println("\n[3/4] Calculating specificity and boost scores...")
	calculateBoostScores(taxonomy, trainingData)

	// Step 4: Save taxonomy
	fmt.Println("\n[4/4] Saving pattern taxonomy...")
	if err := saveJSON(PatternTaxonomyPath, taxonomy); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving taxonomy: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Saved to %s\n", PatternTaxonomyPath)

	// Display summary
	displaySummary(taxonomy)

	fmt.Println("\nPattern taxonomy generated successfully!")
	fmt.Println("Use this file in phase3-classifier.go for data-driven pattern boosting")
}

// -------------------- Data Loading --------------------

func loadTrainingData(path string) ([]CVETrainingExample, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var trainingData []CVETrainingExample
	if err := json.Unmarshal(data, &trainingData); err != nil {
		return nil, err
	}

	return trainingData, nil
}

// -------------------- Pattern Taxonomy Building --------------------

func buildPatternTaxonomy(trainingData []CVETrainingExample) *PatternTaxonomy {
	// Group CVEs by attack vector
	vectorCVEs := make(map[string][]string) // vector -> CVE descriptions
	vectorCounts := make(map[string]int)

	for _, example := range trainingData {
		for _, vector := range example.AttackVectors {
			vectorCVEs[vector] = append(vectorCVEs[vector], example.Description)
			vectorCounts[vector]++
		}
	}

	// Extract discriminative terms for each vector
	taxonomy := &PatternTaxonomy{
		Patterns: make(map[string][]PatternRule),
		Stats: TaxonomyStats{
			TotalVectors: len(vectorCVEs),
			VectorCounts: vectorCounts,
			TopPatterns:  make(map[string][]PatternRule),
		},
	}

	// Calculate TF-IDF for each vector
	docFreq := calculateDocumentFrequency(trainingData)
	totalDocs := float64(len(trainingData))

	for vector, descriptions := range vectorCVEs {
		// Calculate term frequency for this vector
		termFreq := make(map[string]int)
		for _, desc := range descriptions {
			terms := tokenize(desc)
			for _, term := range terms {
				termFreq[term]++
			}
		}

		// Calculate TF-IDF scores
		termScores := make([]TermScore, 0)
		for term, tf := range termFreq {
			if tf < MinTermFrequency {
				continue
			}

			// TF (normalized by vector size)
			tfNorm := float64(tf) / float64(len(descriptions))

			// IDF
			df := float64(docFreq[term])
			idf := math.Log(totalDocs / (1.0 + df))

			// TF-IDF
			tfidf := tfNorm * idf

			// Specificity: how often this term appears in this vector vs others
			termInVector := float64(tf)
			termTotal := float64(docFreq[term])
			specificity := termInVector / termTotal

			if specificity >= MinSpecificity {
				termScores = append(termScores, TermScore{
					Term:        term,
					TF:          tfNorm,
					IDF:         idf,
					TFIDF:       tfidf,
					Specificity: specificity,
					Support:     tf,
				})
			}
		}

		// Sort by TF-IDF score (descending)
		sort.Slice(termScores, func(i, j int) bool {
			return termScores[i].TFIDF > termScores[j].TFIDF
		})

		// Create pattern rules from top terms
		patterns := make([]PatternRule, 0)
		topN := min(MaxPatternsPerVector, len(termScores))

		for i := 0; i < topN; i++ {
			ts := termScores[i]

			// Single-keyword pattern
			pattern := PatternRule{
				Keywords:    []string{ts.Term},
				Specificity: ts.Specificity,
				Boost:       0.0, // Will be calculated later
				Support:     ts.Support,
			}
			patterns = append(patterns, pattern)
		}

		taxonomy.Patterns[vector] = patterns
		taxonomy.Stats.TopPatterns[vector] = patterns[:min(5, len(patterns))]
	}

	taxonomy.Stats.TotalPatterns = countTotalPatterns(taxonomy)

	return taxonomy
}

// -------------------- Boost Score Calculation --------------------

func calculateBoostScores(taxonomy *PatternTaxonomy, trainingData []CVETrainingExample) {
	// Calculate boost based on specificity and support
	// Boost = base_boost * specificity * log(support)

	const baseBoost = 50.0

	for vector, patterns := range taxonomy.Patterns {
		for i := range patterns {
			pattern := &patterns[i]

			// Boost increases with specificity and support
			supportFactor := math.Log(float64(pattern.Support) + 1.0)
			pattern.Boost = baseBoost * pattern.Specificity * supportFactor

			// Clamp boost to reasonable range
			if pattern.Boost < 10.0 {
				pattern.Boost = 10.0
			} else if pattern.Boost > 100.0 {
				pattern.Boost = 100.0
			}
		}
		taxonomy.Patterns[vector] = patterns
	}
}

// -------------------- Term Extraction --------------------

func extractAllTerms(trainingData []CVETrainingExample) map[string]bool {
	allTerms := make(map[string]bool)
	for _, example := range trainingData {
		terms := tokenize(example.Description)
		for _, term := range terms {
			allTerms[term] = true
		}
	}
	return allTerms
}

func calculateDocumentFrequency(trainingData []CVETrainingExample) map[string]int {
	docFreq := make(map[string]int)

	for _, example := range trainingData {
		terms := tokenize(example.Description)
		seen := make(map[string]bool)

		for _, term := range terms {
			if !seen[term] {
				docFreq[term]++
				seen[term] = true
			}
		}
	}

	return docFreq
}

// -------------------- Tokenization --------------------

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

	// Enhanced stopword list (security-specific)
	stopwords := map[string]bool{
		// Common English
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"that": true, "this": true, "are": true, "was": true, "were": true,
		"been": true, "being": true, "have": true, "has": true, "had": true,
		"but": true, "not": true, "can": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true,
		"into": true, "through": true, "during": true, "before": true, "after": true,

		// Generic security terms (too common to be discriminative)
		"vulnerability": true, "allows": true, "attacker": true, "remote": true,
		"via": true, "user": true, "application": true, "system": true,
		"version": true, "versions": true, "prior": true, "component": true,
	}

	filtered := make([]string, 0, len(words))
	for _, word := range words {
		if !stopwords[word] && len(word) >= MinPatternLength {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// -------------------- Display --------------------

func displaySummary(taxonomy *PatternTaxonomy) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("PATTERN TAXONOMY SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total Attack Vectors:  %d\n", taxonomy.Stats.TotalVectors)
	fmt.Printf("Total Patterns:        %d\n", taxonomy.Stats.TotalPatterns)
	fmt.Printf("Avg Patterns/Vector:   %.1f\n",
		float64(taxonomy.Stats.TotalPatterns)/float64(taxonomy.Stats.TotalVectors))

	// Show top 5 vectors by pattern count
	fmt.Println("\nTop 5 Vectors by Training Data Size:")
	vectorCounts := make([]struct {
		Vector string
		Count  int
	}, 0, len(taxonomy.Stats.VectorCounts))

	for vector, count := range taxonomy.Stats.VectorCounts {
		vectorCounts = append(vectorCounts, struct {
			Vector string
			Count  int
		}{vector, count})
	}

	sort.Slice(vectorCounts, func(i, j int) bool {
		return vectorCounts[i].Count > vectorCounts[j].Count
	})

	for i := 0; i < min(5, len(vectorCounts)); i++ {
		vc := vectorCounts[i]
		patterns := taxonomy.Patterns[vc.Vector]
		fmt.Printf("  %d. %-30s %5d CVEs, %2d patterns\n",
			i+1, vc.Vector, vc.Count, len(patterns))

		// Show top 3 patterns
		for j := 0; j < min(3, len(patterns)); j++ {
			p := patterns[j]
			fmt.Printf("     - %-20s (spec: %.2f, boost: %.1f, support: %d)\n",
				strings.Join(p.Keywords, ", "), p.Specificity, p.Boost, p.Support)
		}
	}

	// Show example patterns for deserialization
	if patterns, exists := taxonomy.Patterns["deserialization"]; exists {
		fmt.Println("\nExample: Deserialization Patterns (Top 10):")
		for i := 0; i < min(10, len(patterns)); i++ {
			p := patterns[i]
			fmt.Printf("  %2d. %-20s spec=%.2f boost=%.1f support=%d\n",
				i+1, strings.Join(p.Keywords, ", "), p.Specificity, p.Boost, p.Support)
		}
	}
}

// -------------------- Utilities --------------------

func countTotalPatterns(taxonomy *PatternTaxonomy) int {
	total := 0
	for _, patterns := range taxonomy.Patterns {
		total += len(patterns)
	}
	return total
}

func saveJSON(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, jsonData, 0644)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
