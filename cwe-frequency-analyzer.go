package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// Training data structure
type CVEEntry struct {
	CVEID         string   `json:"cve_id"`
	Description   string   `json:"description"`
	CWEs          []string `json:"cwes"`
	AttackVectors []string `json:"attack_vectors"`
	PublishedDate string   `json:"published_date"`
}

// CWE frequency data
type CWEFrequency struct {
	CWEID      string  `json:"cwe_id"`
	Count      int     `json:"count"`
	Percentage float64 `json:"percentage"`
	Rank       int     `json:"rank"`
}

// Attack vector statistics
type VectorStats struct {
	TotalCVEs      int            `json:"total_cves"`
	CWEFrequencies []CWEFrequency `json:"cwe_frequencies"`
	TopCWEs        []string       `json:"top_cwes"`   // Top 10 CWE IDs
	CWECounts      map[string]int `json:"cwe_counts"` // Full CWE -> count mapping
}

// Output structure
type CWEFrequencyMap struct {
	GeneratedAt   string                  `json:"generated_at"`
	TotalCVEs     int                     `json:"total_cves"`
	AttackVectors map[string]*VectorStats `json:"attack_vectors"`
	GlobalTopCWEs []CWEFrequency          `json:"global_top_cwes"` // Top CWEs across all vectors
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println("CWE Frequency Analyzer")
	fmt.Println("Generates statistical CWE frequency map from training data")
	fmt.Println("=================================================================\n")

	resourcesPath := "/home/ubuntu/cwecapec/resources"
	inputPath := resourcesPath + "/training_data_reclassified.json"
	outputPath := resourcesPath + "/cwe_frequency_map.json"

	// Load training data
	fmt.Printf("Loading training data from %s... ", inputPath)
	trainingData, err := loadTrainingData(inputPath)
	if err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ (%d CVEs loaded)\n\n", len(trainingData))

	// Analyze frequencies
	fmt.Println("Analyzing CWE frequencies by attack vector...")
	frequencyMap := analyzeFrequencies(trainingData)

	// Display statistics
	displayStatistics(frequencyMap)

	// Save results
	fmt.Printf("\nSaving frequency map to %s... ", outputPath)
	if err := saveFrequencyMap(frequencyMap, outputPath); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	fmt.Println("\n=================================================================")
	fmt.Println("Analysis complete!")
	fmt.Println("=================================================================")
}

func loadTrainingData(path string) ([]CVEEntry, error) {
	file, err := os.Open(path)
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

func analyzeFrequencies(entries []CVEEntry) *CWEFrequencyMap {
	frequencyMap := &CWEFrequencyMap{
		GeneratedAt:   fmt.Sprintf("%v", os.Getenv("TZ")),
		TotalCVEs:     len(entries),
		AttackVectors: make(map[string]*VectorStats),
	}

	// Track global CWE frequencies
	globalCWECounts := make(map[string]int)

	// Process each CVE
	for _, entry := range entries {
		// Track global CWE counts
		for _, cweID := range entry.CWEs {
			globalCWECounts[cweID]++
		}

		// Track per-vector CWE counts
		for _, vector := range entry.AttackVectors {
			if _, exists := frequencyMap.AttackVectors[vector]; !exists {
				frequencyMap.AttackVectors[vector] = &VectorStats{
					CWECounts: make(map[string]int),
				}
			}

			stats := frequencyMap.AttackVectors[vector]
			stats.TotalCVEs++

			for _, cweID := range entry.CWEs {
				stats.CWECounts[cweID]++
			}
		}
	}

	// Calculate frequencies and rankings for each attack vector
	for _, stats := range frequencyMap.AttackVectors {
		stats.CWEFrequencies = calculateFrequencies(stats.CWECounts, stats.TotalCVEs)
		stats.TopCWEs = getTopCWEs(stats.CWEFrequencies, 10)
	}

	// Calculate global top CWEs
	frequencyMap.GlobalTopCWEs = calculateFrequencies(globalCWECounts, len(entries))

	return frequencyMap
}

func calculateFrequencies(cweCounts map[string]int, totalCVEs int) []CWEFrequency {
	var frequencies []CWEFrequency

	for cweID, count := range cweCounts {
		percentage := float64(count) * 100.0 / float64(totalCVEs)
		frequencies = append(frequencies, CWEFrequency{
			CWEID:      cweID,
			Count:      count,
			Percentage: percentage,
		})
	}

	// Sort by count (descending)
	sort.Slice(frequencies, func(i, j int) bool {
		return frequencies[i].Count > frequencies[j].Count
	})

	// Assign ranks
	for i := range frequencies {
		frequencies[i].Rank = i + 1
	}

	return frequencies
}

func getTopCWEs(frequencies []CWEFrequency, n int) []string {
	var topCWEs []string
	for i := 0; i < n && i < len(frequencies); i++ {
		topCWEs = append(topCWEs, frequencies[i].CWEID)
	}
	return topCWEs
}

func saveFrequencyMap(frequencyMap *CWEFrequencyMap, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(frequencyMap)
}

func displayStatistics(frequencyMap *CWEFrequencyMap) {
	fmt.Println("\n=================================================================")
	fmt.Println("Global Statistics")
	fmt.Println("=================================================================")
	fmt.Printf("Total CVEs analyzed: %d\n", frequencyMap.TotalCVEs)
	fmt.Printf("Attack vectors found: %d\n\n", len(frequencyMap.AttackVectors))

	fmt.Println("Top 20 CWEs (across all attack vectors):")
	for i := 0; i < 20 && i < len(frequencyMap.GlobalTopCWEs); i++ {
		cwe := frequencyMap.GlobalTopCWEs[i]
		fmt.Printf("  %2d. CWE-%s: %5d CVEs (%.2f%%)\n",
			cwe.Rank, cwe.CWEID, cwe.Count, cwe.Percentage)
	}

	fmt.Println("\n=================================================================")
	fmt.Println("Attack Vector Statistics")
	fmt.Println("=================================================================")

	// Sort attack vectors by CVE count
	type vectorCount struct {
		vector string
		count  int
	}

	var vectors []vectorCount
	for vector, stats := range frequencyMap.AttackVectors {
		vectors = append(vectors, vectorCount{vector, stats.TotalCVEs})
	}

	sort.Slice(vectors, func(i, j int) bool {
		return vectors[i].count > vectors[j].count
	})

	// Display top 15 attack vectors
	fmt.Println("\nTop 15 attack vectors by CVE count:")
	for i := 0; i < 15 && i < len(vectors); i++ {
		vc := vectors[i]
		stats := frequencyMap.AttackVectors[vc.vector]

		fmt.Printf("\n%2d. %s (%d CVEs)\n", i+1, vc.vector, vc.count)
		fmt.Println("    Top 5 CWEs:")

		for j := 0; j < 5 && j < len(stats.CWEFrequencies); j++ {
			cwe := stats.CWEFrequencies[j]
			fmt.Printf("      - CWE-%s: %d CVEs (%.1f%%)\n",
				cwe.CWEID, cwe.Count, cwe.Percentage)
		}
	}
}
