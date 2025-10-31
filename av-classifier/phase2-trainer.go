package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Training data structures (from Phase 1)
type TrainingRecord struct {
	CVEID         string   `json:"cve_id"`
	Description   string   `json:"description"`
	CWEs          []string `json:"cwes"`
	AttackVectors []string `json:"attack_vectors"`
	PublishedDate string   `json:"published_date"`
}

// Naive Bayes model structures
type NaiveBayesModel struct {
	AttackVectors   []string                      `json:"attack_vectors"`
	VectorPriors    map[string]float64            `json:"vector_priors"`     // P(vector)
	WordGivenVector map[string]map[string]float64 `json:"word_given_vector"` // P(word|vector)
	WordCounts      map[string]map[string]int     `json:"word_counts"`       // Count of word in vector
	TotalWords      map[string]int                `json:"total_words"`       // Total words per vector
	Vocabulary      []string                      `json:"vocabulary"`        // All unique words
	TotalDocuments  int                           `json:"total_documents"`
	VectorDocCounts map[string]int                `json:"vector_doc_counts"` // Documents per vector
}

// Stopwords to filter out
var stopwords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "by": true, "for": true, "from": true, "has": true, "he": true,
	"in": true, "is": true, "it": true, "its": true, "of": true, "on": true,
	"that": true, "the": true, "to": true, "was": true, "will": true, "with": true,
	"this": true, "but": true, "they": true, "have": true, "had": true, "what": true,
	"when": true, "where": true, "who": true, "which": true, "why": true, "how": true,
	"can": true, "could": true, "may": true, "might": true, "must": true, "shall": true,
	"should": true, "would": true, "or": true, "not": true, "no": true, "nor": true,
	"if": true, "then": true, "than": true, "so": true, "such": true, "only": true,
	"own": true, "same": true, "some": true, "these": true, "those": true, "very": true,
	"also": true, "just": true, "more": true, "most": true, "other": true, "into": true,
	"through": true, "during": true, "before": true, "after": true, "above": true,
	"below": true, "between": true, "under": true, "again": true, "further": true,
	"once": true, "here": true, "there": true, "all": true, "both": true, "each": true,
	"few": true, "any": true, "been": true, "being": true, "do": true, "does": true,
	"did": true, "doing": true, "out": true, "off": true, "over": true, "up": true,
	"down": true, "about": true, "against": true, "because": true, "until": true,
	"while": true, "within": true, "along": true, "following": true, "across": true,
	"behind": true, "beyond": true, "plus": true, "except": true, "however": true,
	"nor": true, "since": true, "unless": true, "whereas": true, "whether": true,
}

// Tokenize and clean text
func tokenize(text string) []string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove version numbers (e.g., "2.15.0", "v1.2.3")
	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")

	// Remove CVE IDs
	cveRegex := regexp.MustCompile(`cve-\d{4}-\d+`)
	text = cveRegex.ReplaceAllString(text, "")

	// Extract words (alphanumeric sequences)
	wordRegex := regexp.MustCompile(`[a-z][a-z0-9]*`)
	words := wordRegex.FindAllString(text, -1)

	// Filter stopwords and short words
	var filtered []string
	for _, word := range words {
		if len(word) >= 3 && !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// Train Naive Bayes model
func trainNaiveBayes(trainingData []TrainingRecord) *NaiveBayesModel {
	model := &NaiveBayesModel{
		VectorPriors:    make(map[string]float64),
		WordGivenVector: make(map[string]map[string]float64),
		WordCounts:      make(map[string]map[string]int),
		TotalWords:      make(map[string]int),
		VectorDocCounts: make(map[string]int),
		TotalDocuments:  len(trainingData),
	}

	// Collect all unique attack vectors
	vectorSet := make(map[string]bool)
	for _, record := range trainingData {
		for _, vector := range record.AttackVectors {
			vectorSet[vector] = true
		}
	}
	for vector := range vectorSet {
		model.AttackVectors = append(model.AttackVectors, vector)
		model.WordCounts[vector] = make(map[string]int)
	}

	// Build vocabulary and count words
	vocabSet := make(map[string]bool)

	fmt.Println("Tokenizing descriptions and counting words...")
	for i, record := range trainingData {
		if (i+1)%100 == 0 {
			fmt.Printf("  Processed %d/%d records\n", i+1, len(trainingData))
		}

		words := tokenize(record.Description)

		// Add to vocabulary
		for _, word := range words {
			vocabSet[word] = true
		}

		// Count words for each attack vector
		for _, vector := range record.AttackVectors {
			model.VectorDocCounts[vector]++
			for _, word := range words {
				model.WordCounts[vector][word]++
				model.TotalWords[vector]++
			}
		}
	}

	// Convert vocabulary set to slice
	for word := range vocabSet {
		model.Vocabulary = append(model.Vocabulary, word)
	}

	fmt.Printf("✓ Vocabulary size: %d unique words\n\n", len(model.Vocabulary))

	// Calculate priors: P(vector) = count(vector) / total_documents
	fmt.Println("Calculating prior probabilities...")
	for vector := range vectorSet {
		model.VectorPriors[vector] = float64(model.VectorDocCounts[vector]) / float64(model.TotalDocuments)
		fmt.Printf("  P(%s) = %.4f (%d documents)\n", vector, model.VectorPriors[vector], model.VectorDocCounts[vector])
	}

	// Calculate likelihoods with Laplace smoothing: P(word|vector)
	fmt.Println("\nCalculating word likelihoods with Laplace smoothing...")
	vocabularySize := len(model.Vocabulary)

	for _, vector := range model.AttackVectors {
		model.WordGivenVector[vector] = make(map[string]float64)
		totalWordsInVector := model.TotalWords[vector]

		for _, word := range model.Vocabulary {
			wordCount := model.WordCounts[vector][word]
			// Laplace smoothing: (count + 1) / (total + vocabulary_size)
			model.WordGivenVector[vector][word] = float64(wordCount+1) / float64(totalWordsInVector+vocabularySize)
		}
	}

	fmt.Printf("✓ Calculated likelihoods for %d words across %d attack vectors\n", vocabularySize, len(model.AttackVectors))

	return model
}

// Find top words for each attack vector (for analysis)
func findTopWords(model *NaiveBayesModel, topN int) map[string][]WordScore {
	result := make(map[string][]WordScore)

	for _, vector := range model.AttackVectors {
		var scores []WordScore
		for word, prob := range model.WordGivenVector[vector] {
			count := model.WordCounts[vector][word]
			if count >= 3 { // Only consider words that appear at least 3 times
				scores = append(scores, WordScore{Word: word, Score: prob, Count: count})
			}
		}

		// Sort by probability (descending)
		for i := 0; i < len(scores); i++ {
			for j := i + 1; j < len(scores); j++ {
				if scores[j].Score > scores[i].Score {
					scores[i], scores[j] = scores[j], scores[i]
				}
			}
		}

		// Take top N
		if len(scores) > topN {
			scores = scores[:topN]
		}

		result[vector] = scores
	}

	return result
}

type WordScore struct {
	Word  string  `json:"word"`
	Score float64 `json:"score"`
	Count int     `json:"count"`
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println("Phase 2: Naive Bayes Trainer for Attack Vector Detection")
	fmt.Println("=================================================================\n")

	// Load training data from Phase 1
	inputFile := "training_data.json"
	outputModel := "naive_bayes_model.json"

	fmt.Printf("Loading training data from: %s\n", inputFile)

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("❌ Error opening file: %v\n", err)
		fmt.Println("\nMake sure you've run phase1-collector first to generate training_data.json")
		os.Exit(1)
	}
	defer file.Close()

	var trainingData []TrainingRecord
	if err := json.NewDecoder(file).Decode(&trainingData); err != nil {
		fmt.Printf("❌ Error decoding JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Loaded %d training records\n\n", len(trainingData))

	// Train model
	fmt.Println("Training Naive Bayes model...")
	fmt.Println("=================================================================")
	model := trainNaiveBayes(trainingData)

	// Find top words for analysis
	fmt.Println("\n=================================================================")
	fmt.Println("Top discriminative words per attack vector:")
	fmt.Println("=================================================================")
	topWords := findTopWords(model, 15)

	for _, vector := range model.AttackVectors {
		if words, ok := topWords[vector]; ok && len(words) > 0 {
			fmt.Printf("\n%s:\n", strings.ToUpper(vector))
			for i, ws := range words {
				if i >= 10 { // Show top 10 in console
					break
				}
				fmt.Printf("  %2d. %-20s (count: %4d, prob: %.6f)\n", i+1, ws.Word, ws.Count, ws.Score)
			}
		}
	}

	// Save model
	fmt.Println("\n=================================================================")
	fmt.Printf("Saving model to: %s\n", outputModel)

	outFile, err := os.Create(outputModel)
	if err != nil {
		fmt.Printf("❌ Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	encoder := json.NewEncoder(outFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(model); err != nil {
		fmt.Printf("❌ Error writing model: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Model saved successfully!")

	// Model statistics
	fmt.Println("\n=================================================================")
	fmt.Println("Model Statistics:")
	fmt.Println("=================================================================")
	fmt.Printf("  Attack vectors: %d\n", len(model.AttackVectors))
	fmt.Printf("  Vocabulary size: %d words\n", len(model.Vocabulary))
	fmt.Printf("  Training documents: %d\n", model.TotalDocuments)

	totalWords := 0
	for _, count := range model.TotalWords {
		totalWords += count
	}
	fmt.Printf("  Total words processed: %d\n", totalWords)

	fmt.Println("\n✓ Phase 2 complete! Ready for Phase 3 (Attack vector classifier)")
}
