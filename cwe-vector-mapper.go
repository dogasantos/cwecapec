package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Structures to read the frequency map
type CWEFrequency struct {
	CWEID      string  `json:"cwe_id"`
	Count      int     `json:"count"`
	Percentage float64 `json:"percentage"`
	Rank       int     `json:"rank"`
}

type VectorStats struct {
	TotalCVEs      int            `json:"total_cves"`
	CWEFrequencies []CWEFrequency `json:"cwe_frequencies"`
	TopCWEs        []string       `json:"top_cwes"`
	CWECounts      map[string]int `json:"cwe_counts"`
}

type CWEFrequencyMap struct {
	GeneratedAt   string                  `json:"generated_at"`
	TotalCVEs     int                     `json:"total_cves"`
	AttackVectors map[string]*VectorStats `json:"attack_vectors"`
	GlobalTopCWEs []CWEFrequency          `json:"global_top_cwes"`
}

// Output structure
type AttackVectorToCWEsMap map[string][]string

const (
	resourcesPath = "resources"
	inputPath     = resourcesPath + "/cwe_frequency_map.json"
	outputPath    = resourcesPath + "/attack_vector_to_cwe_map.json"
	topN          = 5 // Number of top CWEs to include for each vector
)

func main() {
	fmt.Println("=================================================================")
	fmt.Println("CWE Vector Mapper")
	fmt.Printf("Generates simplified Attack Vector -> Top %d CWEs map\n", topN)
	fmt.Println("=================================================================\n")

	// Load frequency map
	fmt.Printf("Loading frequency map from %s... ", inputPath)
	freqMap, err := loadFrequencyMap(inputPath)
	if err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Generate the simplified map
	fmt.Printf("Generating Attack Vector -> Top %d CWEs map... ", topN)
	simplifiedMap := generateSimplifiedMap(freqMap)
	fmt.Println("✓")

	// Save results
	fmt.Printf("Saving results to %s... ", outputPath)
	if err := saveSimplifiedMap(simplifiedMap, outputPath); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Display a sample
	displaySample(simplifiedMap)
}

func loadFrequencyMap(path string) (*CWEFrequencyMap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	freqMap := &CWEFrequencyMap{}
	if err := json.Unmarshal(data, freqMap); err != nil {
		return nil, err
	}

	return freqMap, nil
}

func generateSimplifiedMap(freqMap *CWEFrequencyMap) AttackVectorToCWEsMap {
	simplifiedMap := make(AttackVectorToCWEsMap)

	// Sort vectors by total CVEs for consistent output
	var vectors []string
	for vector := range freqMap.AttackVectors {
		vectors = append(vectors, vector)
	}
	sort.Strings(vectors)

	for _, vector := range vectors {
		stats := freqMap.AttackVectors[vector]
		var topCWEs []string

		// Use the full CWEFrequencies list to ensure we get the most frequent
		for i := 0; i < topN && i < len(stats.CWEFrequencies); i++ {
			// Prepend "CWE-" for clarity, although the user's current data uses raw IDs
			// Sticking to raw IDs for compatibility with existing Go code
			topCWEs = append(topCWEs, stats.CWEFrequencies[i].CWEID)
		}

		if len(topCWEs) > 0 {
			simplifiedMap[vector] = topCWEs
		}
	}

	return simplifiedMap
}

func saveSimplifiedMap(simplifiedMap AttackVectorToCWEsMap, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(simplifiedMap)
}

func displaySample(simplifiedMap AttackVectorToCWEsMap) {
	fmt.Println("\n=================================================================")
	fmt.Println("Sample of Generated Map (Attack Vector -> Top CWEs)")
	fmt.Println("=================================================================")

	// Display a few key vectors
	keys := []string{"xss", "sql_injection", "rce", "path_traversal", "deserialization"}

	for _, key := range keys {
		if cwes, exists := simplifiedMap[key]; exists {
			fmt.Printf("%-18s: [%s]\n", strings.ToUpper(key), strings.Join(cwes, ", "))
		}
	}
	fmt.Println("...")
}
