package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
)

// Training data structures
type CVETrainingData struct {
	CVEID       string `json:"cve_id"`
	Description string `json:"description"`
}

type CAPECData struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// TF-IDF Model
type TFIDFModel struct {
	Vocabulary    map[string]int       `json:"vocabulary"`     // word -> index
	IDF           map[string]float64   `json:"idf"`            // word -> IDF score
	DocumentCount int                  `json:"document_count"` // total documents
	CAPECVectors  map[string][]float64 `json:"capec_vectors"`  // CAPEC-ID -> TF-IDF vector
}

// Tokenize text into words
func tokenize(text string) []string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove special characters, keep only alphanumeric and spaces
	re := regexp.MustCompile(`[^a-z0-9\s]+`)
	text = re.ReplaceAllString(text, " ")

	// Split into words
	words := strings.Fields(text)

	// Filter stop words and short words
	stopwords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"but": true, "in": true, "on": true, "at": true, "to": true,
		"for": true, "of": true, "with": true, "by": true, "from": true,
		"as": true, "is": true, "was": true, "are": true, "were": true,
		"be": true, "been": true, "being": true, "have": true, "has": true,
		"had": true, "do": true, "does": true, "did": true, "will": true,
		"would": true, "could": true, "should": true, "may": true, "might": true,
		"can": true, "this": true, "that": true, "these": true, "those": true,
		"it": true, "its": true, "they": true, "them": true, "their": true,
	}

	filtered := []string{}
	for _, word := range words {
		if len(word) >= 3 && !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// Calculate term frequency for a document
func calculateTF(tokens []string) map[string]float64 {
	tf := make(map[string]float64)
	total := float64(len(tokens))

	// Count occurrences
	for _, token := range tokens {
		tf[token]++
	}

	// Normalize by total count
	for token := range tf {
		tf[token] = tf[token] / total
	}

	return tf
}

// Build vocabulary from all documents
func buildVocabulary(allTokens [][]string) map[string]int {
	wordSet := make(map[string]bool)

	for _, tokens := range allTokens {
		for _, token := range tokens {
			wordSet[token] = true
		}
	}

	// Convert to indexed vocabulary
	vocab := make(map[string]int)
	idx := 0
	for word := range wordSet {
		vocab[word] = idx
		idx++
	}

	return vocab
}

// Calculate IDF scores
func calculateIDF(allTokens [][]string, vocab map[string]int) map[string]float64 {
	docCount := float64(len(allTokens))
	documentFrequency := make(map[string]int)

	// Count how many documents contain each word
	for _, tokens := range allTokens {
		seen := make(map[string]bool)
		for _, token := range tokens {
			if !seen[token] {
				documentFrequency[token]++
				seen[token] = true
			}
		}
	}

	// Calculate IDF: log(N / df)
	idf := make(map[string]float64)
	for word := range vocab {
		df := float64(documentFrequency[word])
		if df > 0 {
			idf[word] = math.Log(docCount / df)
		} else {
			idf[word] = 0
		}
	}

	return idf
}

// Normalize vector to unit length (L2 normalization)
func normalizeVector(vector []float64) []float64 {
	var norm float64
	for _, val := range vector {
		norm += val * val
	}
	norm = math.Sqrt(norm)

	if norm == 0 {
		return vector
	}

	normalized := make([]float64, len(vector))
	for i, val := range vector {
		normalized[i] = val / norm
	}

	return normalized
}

// Convert TF map to TF-IDF vector (normalized)
func tfToVector(tf map[string]float64, idf map[string]float64, vocab map[string]int) []float64 {
	vector := make([]float64, len(vocab))

	for word, tfScore := range tf {
		if idx, exists := vocab[word]; exists {
			vector[idx] = tfScore * idf[word]
		}
	}

	// ✅ NORMALIZE THE VECTOR
	return normalizeVector(vector)
}

func main() {
	fmt.Println("================================================================================")
	fmt.Println("TF-IDF MODEL TRAINING (WITH NORMALIZATION)")
	fmt.Println("================================================================================")
	fmt.Println()

	// Step 1: Load CVE training data
	fmt.Println("[1/5] Loading CVE training data...")
	cveData, err := os.ReadFile("resources/training_data.json")
	if err != nil {
		fmt.Printf("Error loading CVE data: %v\n", err)
		return
	}

	var cves []CVETrainingData
	if err := json.Unmarshal(cveData, &cves); err != nil {
		fmt.Printf("Error parsing CVE data: %v\n", err)
		return
	}
	fmt.Printf("  Loaded %d CVEs\n\n", len(cves))

	// Step 2: Load CAPEC database
	fmt.Println("[2/5] Loading CAPEC database...")
	capecData, err := os.ReadFile("resources/capec_db.json")
	if err != nil {
		fmt.Printf("Error loading CAPEC data: %v\n", err)
		return
	}

	var capecDB map[string]CAPECData
	if err := json.Unmarshal(capecData, &capecDB); err != nil {
		fmt.Printf("Error parsing CAPEC data: %v\n", err)
		return
	}
	fmt.Printf("  Loaded %d CAPECs\n\n", len(capecDB))

	// Step 3: Tokenize all documents
	fmt.Println("[3/5] Tokenizing documents...")
	allTokens := [][]string{}

	// Tokenize CVEs
	fmt.Printf("  Tokenizing CVEs...")
	for i, cve := range cves {
		tokens := tokenize(cve.Description)
		allTokens = append(allTokens, tokens)

		if (i+1)%5000 == 0 {
			fmt.Printf("\r  Tokenizing CVEs... %d/%d", i+1, len(cves))
		}
	}
	fmt.Printf("\r  Tokenizing CVEs... %d/%d ✓\n", len(cves), len(cves))

	// Tokenize CAPECs
	capecTokens := make(map[string][]string)
	fmt.Printf("  Tokenizing CAPECs...")
	idx := 0
	for id, capec := range capecDB {
		text := capec.Name + " " + capec.Description
		tokens := tokenize(text)
		capecTokens[id] = tokens
		allTokens = append(allTokens, tokens)
		idx++

		if idx%100 == 0 {
			fmt.Printf("\r  Tokenizing CAPECs... %d/%d", idx, len(capecDB))
		}
	}
	fmt.Printf("\r  Tokenizing CAPECs... %d/%d ✓\n\n", len(capecDB), len(capecDB))

	// Step 4: Build TF-IDF model
	fmt.Println("[4/5] Building TF-IDF model...")

	fmt.Print("  Building vocabulary...")
	vocab := buildVocabulary(allTokens)
	fmt.Printf(" %d unique terms ✓\n", len(vocab))

	fmt.Print("  Calculating IDF scores...")
	idf := calculateIDF(allTokens, vocab)
	fmt.Println(" ✓")

	// Pre-compute CAPEC vectors (NORMALIZED)
	fmt.Printf("  Computing CAPEC vectors (normalized)...")
	capecVectors := make(map[string][]float64)
	idx = 0
	for id, tokens := range capecTokens {
		tf := calculateTF(tokens)
		vector := tfToVector(tf, idf, vocab) // Now returns normalized vector
		capecVectors[id] = vector
		idx++

		if idx%100 == 0 {
			fmt.Printf("\r  Computing CAPEC vectors (normalized)... %d/%d", idx, len(capecTokens))
		}
	}
	fmt.Printf("\r  Computing CAPEC vectors (normalized)... %d/%d ✓\n\n", len(capecTokens), len(capecTokens))

	// Step 5: Save model
	fmt.Println("[5/5] Saving TF-IDF model...")

	model := TFIDFModel{
		Vocabulary:    vocab,
		IDF:           idf,
		DocumentCount: len(allTokens),
		CAPECVectors:  capecVectors,
	}

	modelJSON, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling model: %v\n", err)
		return
	}

	if err := os.WriteFile("resources/tfidf_model.json", modelJSON, 0644); err != nil {
		fmt.Printf("Error writing model: %v\n", err)
		return
	}

	// Get file size
	fileInfo, _ := os.Stat("resources/tfidf_model.json")
	sizeKB := float64(fileInfo.Size()) / 1024.0
	sizeMB := sizeKB / 1024.0

	fmt.Printf("  Model saved to: resources/tfidf_model.json\n")
	if sizeMB >= 1.0 {
		fmt.Printf("  File size: %.2f MB\n", sizeMB)
	} else {
		fmt.Printf("  File size: %.2f KB\n", sizeKB)
	}
	fmt.Println()

	// Print statistics
	fmt.Println("================================================================================")
	fmt.Println("[+] TF-IDF MODEL TRAINING COMPLETE")
	fmt.Println("================================================================================")
	fmt.Printf("  Vocabulary size: %d terms\n", len(vocab))
	fmt.Printf("  Training documents: %d CVEs + %d CAPECs = %d total\n",
		len(cves), len(capecDB), len(allTokens))
	fmt.Printf("  Pre-computed CAPEC vectors: %d (NORMALIZED)\n", len(capecVectors))
	fmt.Println()
	fmt.Println("  Usage:")
	fmt.Println("    1. Copy resources/tfidf_model.json to your project")
	fmt.Println("    2. Use the model for offline CAPEC ranking")
	fmt.Println("================================================================================")
}
