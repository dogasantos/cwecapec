// TF-IDF Based CAPEC Scoring Module
// Pure offline scoring using TF-IDF model trained on 2024 CVE dataset

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
)

// TF-IDF Model (loaded from resources/tfidf_model.json)
type TFIDFModel struct {
	Vocabulary    map[string]int       `json:"vocabulary"`
	IDF           map[string]float64   `json:"idf"`
	DocumentCount int                  `json:"document_count"`
	CAPECVectors  map[string][]float64 `json:"capec_vectors"`
}

var tfidfModel *TFIDFModel

// Load TF-IDF model from file
func loadTFIDFModel(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var model TFIDFModel
	if err := json.Unmarshal(data, &model); err != nil {
		return err
	}

	tfidfModel = &model
	return nil
}

// Tokenize text (must match training tokenization)
func tokenizeTFIDF(text string) []string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove special characters
	re := regexp.MustCompile(`[^a-z0-9\s]+`)
	text = re.ReplaceAllString(text, " ")

	// Split and filter
	words := strings.Fields(text)

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

// Calculate TF for tokens
func calculateTFIDFTF(tokens []string) map[string]float64 {
	tf := make(map[string]float64)
	total := float64(len(tokens))

	for _, token := range tokens {
		tf[token]++
	}

	for token := range tf {
		tf[token] = tf[token] / total
	}

	return tf
}

// Convert text to TF-IDF vector
func textToTFIDFVector(text string) []float64 {
	if tfidfModel == nil {
		return nil
	}

	tokens := tokenizeTFIDF(text)
	tf := calculateTFIDFTF(tokens)

	// Create vector
	vector := make([]float64, len(tfidfModel.Vocabulary))

	for word, tfScore := range tf {
		if idx, exists := tfidfModel.Vocabulary[word]; exists {
			if idfScore, hasIDF := tfidfModel.IDF[word]; hasIDF {
				vector[idx] = tfScore * idfScore
			}
		}
	}

	return vector
}

// Calculate cosine similarity between two vectors
func cosineSimilarityTFIDF(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dotProduct, normA, normB float64

	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// Score a CAPEC against a CVE description using TF-IDF
func scoreCAPECWithTFIDF(cveDescription, capecID string) float64 {
	if tfidfModel == nil {
		return 0
	}

	// Get pre-computed CAPEC vector
	capecVector, exists := tfidfModel.CAPECVectors[capecID]
	if !exists {
		return 0
	}

	// Convert CVE description to vector
	cveVector := textToTFIDFVector(cveDescription)
	if cveVector == nil {
		return 0
	}

	// Calculate similarity
	similarity := cosineSimilarityTFIDF(cveVector, capecVector)

	// Scale to 0-100 for consistency with other scoring methods
	return similarity * 100.0
}

// Batch score multiple CAPECs
func scoreCAPECsWithTFIDF(cveDescription string, capecIDs []string) map[string]float64 {
	scores := make(map[string]float64)

	for _, capecID := range capecIDs {
		score := scoreCAPECWithTFIDF(cveDescription, capecID)
		if score > 0 {
			scores[capecID] = score
		}
	}

	return scores
}

// Check if TF-IDF model is loaded
func tfidfAvailable() bool {
	return tfidfModel != nil
}

// Get TF-IDF model statistics
func getTFIDFStats() string {
	if tfidfModel == nil {
		return "not loaded"
	}

	return fmt.Sprintf("%d terms, %d CAPECs",
		len(tfidfModel.Vocabulary), len(tfidfModel.CAPECVectors))
}
