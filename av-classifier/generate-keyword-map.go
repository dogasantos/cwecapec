package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// -------------------- Data Structures --------------------

type CVETrainingExample struct {
	CVEID        string   `json:"cve_id"`
	Description  string   `json:"description"`
	CWEIDs       []string `json:"cwes"`
	AttackVector string   `json:"attack_vector"`
}

type CWEHierarchyInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Abstraction   string   `json:"abstraction"`
	Parents       []string `json:"parents"`
	Children      []string `json:"children"`
	AttackVectors []string `json:"attack_vectors"`
}

type CWEHierarchy struct {
	CWEs                map[string]*CWEHierarchyInfo `json:"cwes"`
	AttackVectorMapping map[string][]string          `json:"attack_vector_mapping"`
}

type CWEInfo struct {
	Name                  string   `json:"name"`
	Description           string   `json:"description,omitempty"`
	ChildOf               []string `json:"childOf,omitempty"`
	RelatedAttackPatterns []string `json:"relatedAttackPatterns,omitempty"`
}

type KeywordPair struct {
	Keyword string
	Count   int
}

type KeywordStats struct {
	TotalKeywords     int                       `json:"total_keywords"`
	TotalCooccurrence int                       `json:"total_cooccurrence"`
	TopKeywords       []KeywordPair             `json:"top_keywords"`
	SampleMappings    map[string][]string       `json:"sample_mappings"`
	FullMap           map[string][]string       `json:"full_map"`
}

// -------------------- Configuration --------------------

const (
	TrainingDataPath  = "resources/training_data.json"
	CWEHierarchyPath  = "resources/cwe_hierarchy.json"
	CWEDBPath         = "resources/cwe_db.json"
	OutputPath        = "resources/keyword_expansion_map.json"
	StatsPath         = "resources/keyword_map_stats.json"
	
	// Configuration
	MinCooccurrence     = 2  // Minimum co-occurrence count to include a keyword (lowered from 5)
	MaxRelatedKeywords  = 10 // Maximum number of related keywords per term
	MinKeywordLength    = 3  // Minimum keyword length
)

// -------------------- Main Function --------------------

func main() 	fmt.Println("Generating Data-Driven Keyword Expansion Map")
	fmt.Println("================================================")
	
	// Step 1: Load training data
	fmt.Println("\n[1/5] Loading CVE training data...")
	trainingData, err := loadTrainingData(TrainingDataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading training data: %v\n", err)
		fmt.Println("ℹ️  Run 'go run av-classifier/phase1-collector.go' to generate training data")
		os.Exit(1)
		fmt.Printf("  Loaded %d CVE examples\n", len(trainingData))
	
	// Step 2: Load CWE data
	fmt.Println("\n[2/5] Loading CWE descriptions...")
	cweDescriptions, err := loadCWEDescriptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CWE data: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Loaded %d CWE descriptions\n", len(cweDescriptions))
	// Step 3: Build co-occurrence matrix
	fmt.Println("\n[3/5] Building keyword co-occurrence matrix...")
	keywordMap, cooccurrenceCounts := buildCooccurrenceMatrix(trainingData, cweDescriptions	fmt.Printf("  Generated mappings for %d keywords\n", len(keywordMap)	fmt.Printf("  Total co-occurrence pairs: %d\n", cooccurrenceCounts)
	
	// Step 4: Save keyword map
	fmt.Println("\n[4/5] Saving keyword expansion map...")
	if err := saveJSON(KeywordMapPath, keywordMap); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving keyword map: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Saved to %s\n", KeywordMapPath)
	
	// Step 5: Generate and save statistics
	fmt.Println("\n[5/5] Generating statistics report...")
	stats := generateStats(keywordMap, cooccurrenceCounts)
	if err := saveJSON(KeywordStatsPath, stats); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving stats: %v\n", err)
		os.Exit(1)
	fmt.Printf("  Saved to %s\n", StatsPath)ath)
	
	// Display summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SUMMARY")fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Total Keywords:        %d\n", stats.TotalKeywords)
	fmt.Printf("Total Co-occurrences:  %d\n", stats.TotalCooccurrence)
	fmt.Printf("Avg Mappings/Keyword:  %.1f\n", float64(stats.TotalCooccurrence)/float64(stats.TotalKeywords))
	fmt.Println("\nTop 10 Most Connected Keywords:")
	for i, kp := range stats.TopKeywords {
		if i >= 10 {
			break
		}
		related := keywordMap[kp.Keyword]
		fmt.Printf("  %2d. %-20s (%d related terms)\n", i+1, kp.Keyword, len(related))
		fmt.Printf("      → %s\n", strings.Join(related[:min(5, len(related))], ", "))
	}
		fmt.Println("\nKeyword expansion map generated successfully!")	fmt.Println("   Use this file in query-report.go for improved CAPEC ranking")
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

func loadCWEDescriptions() (map[string]string, error) {
	descriptions := make(map[string]string)
	
	// Try loading from cwe_hierarchy.json first (has names)
	hierarchyData, err := os.ReadFile(CWEHierarchyPath)
	if err == nil {
		var hierarchy CWEHierarchy
		if err := json.Unmarshal(hierarchyData, &hierarchy); err == nil {
			for cweID, cweInfo := range hierarchy.CWEs {
				descriptions[cweID] = cweInfo.Name
			}
		}
	}
	
	// Also load from cwe_db.json (has more details)
	dbData, err := os.ReadFile(CWEDBPath)
	if err == nil {
		var cweDB map[string]CWEInfo
		if err := json.Unmarshal(dbData, &cweDB); err == nil {
			for cweID, cweInfo := range cweDB {
				// Combine name and description if available
				desc := cweInfo.Name
				if cweInfo.Description != "" {
					desc += " " + cweInfo.Description
				}
				descriptions[cweID] = desc
			}
		}
	}
	
	if len(descriptions) == 0 {
		return nil, fmt.Errorf("no CWE descriptions found")
	}
	
	return descriptions, nil
}

// -------------------- Co-occurrence Matrix Building --------------------

func buildCooccurrenceMatrix(trainingData []CVETrainingExample, cweDescriptions map[string]string) (map[string][]string, int) {
	// Track co-occurrences: keyword1 -> keyword2 -> count
	cooccurrence := make(map[string]map[string]int)
	totalPairs := 0
	
	// Process each CVE example
	for _, example := range trainingData {
		// Tokenize CVE description
		cveTokens := tokenizeForRanking(example.Description)
		cveTokenSet := make(map[string]bool)
		for _, token := range cveTokens {
			cveTokenSet[token] = true
		}
		
		// Tokenize related CWE descriptions
		cweTokenSet := make(map[string]bool)
		for _, cweID := range example.CWEIDs {
			if desc, exists := cweDescriptions[cweID]; exists {
				tokens := tokenizeForRanking(desc)
				for _, token := range tokens {
					cweTokenSet[token] = true
				}
			}
		}
		
		// Record co-occurrences between CVE tokens and CWE tokens
		for cveToken := range cveTokenSet {
			if cooccurrence[cveToken] == nil {
				cooccurrence[cveToken] = make(map[string]int)
			}
			
			for cweToken := range cweTokenSet {
				if cveToken != cweToken { // Don't map a word to itself
					cooccurrence[cveToken][cweToken]++
					totalPairs++
				}
			}
		}
	}
	
	// Convert to keyword map (keep top N related terms)
	keywordMap := make(map[string][]string)
	
	for keyword, relatedMap := range cooccurrence {
		// Convert to sorted list
		pairs := make([]KeywordPair, 0, len(relatedMap))
		for relatedKeyword, count := range relatedMap {
			if count >= MinCooccurrence {
				pairs = append(pairs, KeywordPair{
					Keyword: relatedKeyword,
					Count:   count,
				})
			}
		}
		
		// Sort by count (descending)
		sort.Slice(pairs, func(i, j int) bool {
			return pairs[i].Count > pairs[j].Count
		})
		
		// Keep top N
		topN := min(MaxRelatedKeywords, len(pairs))
		if topN > 0 {
			related := make([]string, topN)
			for i := 0; i < topN; i++ {
				related[i] = pairs[i].Keyword
			}
			keywordMap[keyword] = related
		}
	}
	
	return keywordMap, totalPairs
}

// -------------------- Tokenization --------------------

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
		"into": true, "through": true, "during": true, "before": true, "after": true,
		"above": true, "below": true, "between": true, "under": true, "again": true,
		"further": true, "then": true, "once": true, "here": true, "there": true,
		"when": true, "where": true, "why": true, "how": true, "all": true,
		"each": true, "other": true, "some": true, "such": true, "only": true,
		"own": true, "same": true, "than": true, "too": true, "very": true,
	}
	
	filtered := make([]string, 0, len(words))
	for _, word := range words {
		if !stopwords[word] && len(word) >= MinKeywordLength {
			filtered = append(filtered, word)
		}
	}
	
	return filtered
}

// -------------------- Statistics Generation --------------------

func generateStats(keywordMap map[string][]string, totalCooccurrence int) KeywordStats {
	// Count total related keywords
	totalRelated := 0
	for _, related := range keywordMap {
		totalRelated += len(related)
	}
	
	// Find top keywords by number of relations
	pairs := make([]KeywordPair, 0, len(keywordMap))
	for keyword, related := range keywordMap {
		pairs = append(pairs, KeywordPair{
			Keyword: keyword,
			Count:   len(related),
		})
	}
	
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Count > pairs[j].Count
	})
	
	// Get sample mappings (top 20)
	sampleMappings := make(map[string][]string)
	for i := 0; i < min(20, len(pairs)); i++ {
		keyword := pairs[i].Keyword
		sampleMappings[keyword] = keywordMap[keyword]
	}
	
	return KeywordStats{
		TotalKeywords:     len(keywordMap),
		TotalCooccurrence: totalRelated,
		TopKeywords:       pairs,
		SampleMappings:    sampleMappings,
		FullMap:           keywordMap,
	}
}

// -------------------- Utility Functions --------------------

func saveJSON(filepath string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %w", err)
	}
	
	if err := os.WriteFile(filepath, jsonData, 0644); err != nil {
		return fmt.Errorf("error writing file: %w", err)
	}
	
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
