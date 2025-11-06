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

	// Add manual critical patterns for known important cases
	addManualCriticalPatterns(taxonomy)

	taxonomy.Stats.TotalPatterns = countTotalPatterns(taxonomy)

	return taxonomy
}

// Add manually curated critical patterns for known important cases
// These are patterns that may not appear frequently in training data but are critical
func addManualCriticalPatterns(taxonomy *PatternTaxonomy) {
	manualPatterns := map[string][]PatternRule{
		"deserialization": {
			{Keywords: []string{"jndi"}, Specificity: 0.95, Boost: 50.0, Support: 100},
			{Keywords: []string{"ldap"}, Specificity: 0.90, Boost: 45.0, Support: 80},
			{Keywords: []string{"lookup"}, Specificity: 0.85, Boost: 40.0, Support: 70},
			{Keywords: []string{"unmarsh"}, Specificity: 0.92, Boost: 48.0, Support: 60},
			{Keywords: []string{"pickle"}, Specificity: 0.94, Boost: 47.0, Support: 50},
		},
		"jndi_injection": {
			{Keywords: []string{"jndi"}, Specificity: 0.95, Boost: 50.0, Support: 100},
			{Keywords: []string{"ldap"}, Specificity: 0.90, Boost: 45.0, Support: 80},
			{Keywords: []string{"naming"}, Specificity: 0.85, Boost: 40.0, Support: 60},
		},
		"sql_injection": {
			{Keywords: []string{"union", "select"}, Specificity: 0.95, Boost: 50.0, Support: 200},
			{Keywords: []string{"or", "="}, Specificity: 0.70, Boost: 30.0, Support: 150},
		},
	}

	// Merge manual patterns with generated patterns
	for vector, manualRules := range manualPatterns {
		if existingPatterns, exists := taxonomy.Patterns[vector]; exists {
			// Add manual patterns to the beginning (higher priority)
			taxonomy.Patterns[vector] = append(manualRules, existingPatterns...)
		} else {
			// Create new entry if vector doesn't exist
			taxonomy.Patterns[vector] = manualRules
		}
	}
}

// -------------------- Boost Score Calculation --------------------

func calculateBoostScores(taxonomy *PatternTaxonomy, trainingData []CVETrainingExample) {
	// New scoring system:
	// - High specificity (>0.8) + high support → Strong boost (3.0-5.0)
	// - Medium specificity (0.6-0.8) → Medium boost (1.0-3.0)
	// - Low specificity (<0.6) → Low boost (0.1-1.0)
	// This prevents generic terms from overwhelming specific signals

	// Calculate document frequency for IDF
	docFreq := calculateDocumentFrequency(trainingData)
	totalDocs := float64(len(trainingData))

	for vector, patterns := range taxonomy.Patterns {
		for i := range patterns {
			pattern := &patterns[i]

			// Calculate IDF for the first keyword (most discriminative)
			var idf float64
			if len(pattern.Keywords) > 0 {
				df := float64(docFreq[pattern.Keywords[0]])
				idf = math.Log(totalDocs / (1.0 + df))
			} else {
				idf = 0.0
			}

			// Base boost from specificity
			var baseBoost float64
			if pattern.Specificity >= 0.9 {
				// Very specific (90%+) → Strong signal
				baseBoost = 5.0
			} else if pattern.Specificity >= 0.8 {
				// Highly specific (80-90%) → Good signal
				baseBoost = 3.0
			} else if pattern.Specificity >= 0.7 {
				// Moderately specific (70-80%) → Decent signal
				baseBoost = 2.0
			} else if pattern.Specificity >= 0.6 {
				// Somewhat specific (60-70%) → Weak signal
				baseBoost = 1.0
			} else {
				// Low specificity (<60%) → Very weak signal (penalty)
				baseBoost = 0.1
			}

			// Adjust by IDF (rare terms get higher boost)
			// IDF ranges from ~0 (very common) to ~8 (very rare)
			// Normalize to 0.5-1.5 multiplier
			idfFactor := 0.5 + (idf / 16.0) // Maps IDF 0-8 to 0.5-1.0
			if idfFactor > 1.5 {
				idfFactor = 1.5
			}

			// Adjust by support (more evidence = slightly higher boost)
			// But don't let support dominate (cap at 1.2x)
			supportFactor := 1.0 + math.Log(float64(pattern.Support)+1.0)/20.0
			if supportFactor > 1.2 {
				supportFactor = 1.2
			}

			// Final boost
			pattern.Boost = baseBoost * idfFactor * supportFactor

			// Ensure reasonable range [0.1, 5.0]
			if pattern.Boost < 0.1 {
				pattern.Boost = 0.1
			} else if pattern.Boost > 5.0 {
				pattern.Boost = 5.0
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
