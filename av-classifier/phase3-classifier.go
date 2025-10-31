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

// Naive Bayes model structures
type NaiveBayesModel struct {
	AttackVectors   []string                      `json:"attack_vectors"`
	VectorPriors    map[string]float64            `json:"vector_priors"`
	WordGivenVector map[string]map[string]float64 `json:"word_given_vector"`
	WordCounts      map[string]map[string]int     `json:"word_counts"`
	TotalWords      map[string]int                `json:"total_words"`
	Vocabulary      []string                      `json:"vocabulary"`
	TotalDocuments  int                           `json:"total_documents"`
	VectorDocCounts map[string]int                `json:"vector_doc_counts"`
}

// Classification result
type ClassificationResult struct {
	AttackVector string  `json:"attack_vector"`
	Probability  float64 `json:"probability"`
	LogScore     float64 `json:"log_score"`
	Confidence   string  `json:"confidence"`
}

// Stopwords (same as trainer)
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

// Tokenize text (same as trainer)
func tokenize(text string) []string {
	text = strings.ToLower(text)

	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")

	cveRegex := regexp.MustCompile(`cve-\d{4}-\d+`)
	text = cveRegex.ReplaceAllString(text, "")

	wordRegex := regexp.MustCompile(`[a-z][a-z0-9]*`)
	words := wordRegex.FindAllString(text, -1)

	var filtered []string
	for _, word := range words {
		if len(word) >= 3 && !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// Classify text using Naive Bayes
func classify(text string, model *NaiveBayesModel, topN int) []ClassificationResult {
	words := tokenize(text)

	if len(words) == 0 {
		return []ClassificationResult{}
	}

	// Calculate log probabilities for each attack vector
	// log P(vector|text) = log P(vector) + sum(log P(word|vector))
	scores := make(map[string]float64)

	for _, vector := range model.AttackVectors {
		// Start with prior probability
		logScore := math.Log(model.VectorPriors[vector])

		// Add log likelihood for each word
		for _, word := range words {
			if prob, ok := model.WordGivenVector[vector][word]; ok {
				logScore += math.Log(prob)
			} else {
				// Word not in vocabulary - use smoothed probability
				vocabularySize := len(model.Vocabulary)
				totalWordsInVector := model.TotalWords[vector]
				smoothedProb := 1.0 / float64(totalWordsInVector+vocabularySize)
				logScore += math.Log(smoothedProb)
			}
		}

		scores[vector] = logScore
	}

	// Convert log scores to probabilities using softmax
	// First, find max score for numerical stability
	maxScore := math.Inf(-1)
	for _, score := range scores {
		if score > maxScore {
			maxScore = score
		}
	}

	// Calculate exp(score - maxScore) and sum
	expScores := make(map[string]float64)
	sumExp := 0.0
	for vector, score := range scores {
		expScore := math.Exp(score - maxScore)
		expScores[vector] = expScore
		sumExp += expScore
	}

	// Normalize to get probabilities
	probabilities := make(map[string]float64)
	for vector, expScore := range expScores {
		probabilities[vector] = expScore / sumExp
	}

	// Create results and sort by probability
	var results []ClassificationResult
	for vector, prob := range probabilities {
		confidence := "Low"
		if prob >= 0.7 {
			confidence = "High"
		} else if prob >= 0.4 {
			confidence = "Medium"
		}

		results = append(results, ClassificationResult{
			AttackVector: vector,
			Probability:  prob,
			LogScore:     scores[vector],
			Confidence:   confidence,
		})
	}

	// Sort by probability (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	// Return top N results
	if len(results) > topN {
		results = results[:topN]
	}

	return results
}

// Load model from file
func loadModel(filename string) (*NaiveBayesModel, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var model NaiveBayesModel
	if err := json.NewDecoder(file).Decode(&model); err != nil {
		return nil, err
	}

	return &model, nil
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println("Phase 3: Attack Vector Classifier (Naive Bayes)")
	fmt.Println("=================================================================\n")

	// Check command line arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  ./phase3-classifier \"<CVE description text>\"")
		fmt.Println("  ./phase3-classifier -file <description.txt>")
		fmt.Println("\nExample:")
		fmt.Println("  ./phase3-classifier \"SQL injection vulnerability in login form\"")
		os.Exit(1)
	}

	// Load model
	modelFile := "naive_bayes_model.json"
	fmt.Printf("Loading model from: %s\n", modelFile)

	model, err := loadModel(modelFile)
	if err != nil {
		fmt.Printf("❌ Error loading model: %v\n", err)
		fmt.Println("\nMake sure you've run phase2-trainer first to generate naive_bayes_model.json")
		os.Exit(1)
	}

	fmt.Printf("✓ Model loaded successfully\n")
	fmt.Printf("  Attack vectors: %d\n", len(model.AttackVectors))
	fmt.Printf("  Vocabulary: %d words\n\n", len(model.Vocabulary))

	// Get input text
	var inputText string
	if os.Args[1] == "-file" && len(os.Args) >= 3 {
		// Read from file
		content, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Printf("❌ Error reading file: %v\n", err)
			os.Exit(1)
		}
		inputText = string(content)
	} else {
		// Use command line argument
		inputText = os.Args[1]
	}

	// Classify
	fmt.Println("=================================================================")
	fmt.Println("Input Text:")
	fmt.Println("=================================================================")
	fmt.Println(inputText)
	fmt.Println()

	results := classify(inputText, model, 10)

	if len(results) == 0 {
		fmt.Println("❌ No classification results (input text may be too short or contain no meaningful words)")
		os.Exit(1)
	}

	// Display results
	fmt.Println("=================================================================")
	fmt.Println("Classification Results (Top 10):")
	fmt.Println("=================================================================")
	fmt.Printf("%-30s %12s %12s %s\n", "Attack Vector", "Probability", "Confidence", "Log Score")
	fmt.Println("-----------------------------------------------------------------")

	for i, result := range results {
		fmt.Printf("%2d. %-27s %11.2f%% %12s %10.2f\n",
			i+1,
			strings.ToUpper(result.AttackVector),
			result.Probability*100,
			result.Confidence,
			result.LogScore)
	}

	// Show top prediction
	fmt.Println("\n=================================================================")
	fmt.Println("Top Prediction:")
	fmt.Println("=================================================================")
	top := results[0]
	fmt.Printf("  Attack Vector: %s\n", strings.ToUpper(top.AttackVector))
	fmt.Printf("  Probability: %.2f%%\n", top.Probability*100)
	fmt.Printf("  Confidence: %s\n", top.Confidence)

	// Show all predictions above 5% threshold
	fmt.Println("\n=================================================================")
	fmt.Println("Likely Attack Vectors (>5% probability):")
	fmt.Println("=================================================================")
	hasLikely := false
	for _, result := range results {
		if result.Probability >= 0.05 {
			hasLikely = true
			fmt.Printf("  • %-25s: %6.2f%%\n", strings.ToUpper(result.AttackVector), result.Probability*100)
		}
	}
	if !hasLikely {
		fmt.Println("  (None above threshold)")
	}

	fmt.Println("\n✓ Classification complete!")
}
