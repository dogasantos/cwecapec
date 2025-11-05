package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
)

type TFIDFModel struct {
	Vocabulary    map[string]int       `json:"vocabulary"`
	IDF           map[string]float64   `json:"idf"`
	DocumentCount int                  `json:"document_count"`
	CAPECVectors  map[string][]float64 `json:"capec_vectors"`
}

func vectorNorm(vec []float64) float64 {
	var sum float64
	for _, v := range vec {
		sum += v * v
	}
	return math.Sqrt(sum)
}

func main() {
	fmt.Println("================================================================================")
	fmt.Println("TF-IDF MODEL DIAGNOSTIC")
	fmt.Println("================================================================================")
	fmt.Println()

	// Load model
	data, err := os.ReadFile("resources/tfidf_model.json")
	if err != nil {
		fmt.Printf("Error loading model: %v\n", err)
		return
	}

	var model TFIDFModel
	if err := json.Unmarshal(data, &model); err != nil {
		fmt.Printf("Error parsing model: %v\n", err)
		return
	}

	fmt.Printf("Model Statistics:\n")
	fmt.Printf("  Vocabulary size: %d terms\n", len(model.Vocabulary))
	fmt.Printf("  Document count: %d\n", model.DocumentCount)
	fmt.Printf("  CAPEC vectors: %d\n", len(model.CAPECVectors))
	fmt.Println()

	// Check if vectors are normalized
	fmt.Println("Checking vector normalization...")
	fmt.Println()

	testCAPECs := []string{"242", "77", "35"}

	for _, capecID := range testCAPECs {
		if vec, exists := model.CAPECVectors[capecID]; exists {
			norm := vectorNorm(vec)

			// Count non-zero elements
			nonZero := 0
			for _, v := range vec {
				if v != 0 {
					nonZero++
				}
			}

			fmt.Printf("CAPEC-%s:\n", capecID)
			fmt.Printf("  Vector length: %d\n", len(vec))
			fmt.Printf("  Non-zero elements: %d\n", nonZero)
			fmt.Printf("  L2 Norm: %.6f\n", norm)

			if math.Abs(norm-1.0) < 0.0001 {
				fmt.Printf("  Status: ✅ NORMALIZED (norm ≈ 1.0)\n")
			} else {
				fmt.Printf("  Status: ❌ NOT NORMALIZED (norm should be 1.0)\n")
			}
			fmt.Println()
		} else {
			fmt.Printf("CAPEC-%s: NOT FOUND in model\n\n", capecID)
		}
	}

	// Sample a few IDF values
	fmt.Println("Sample IDF values:")
	count := 0
	for word, idf := range model.IDF {
		if count < 5 {
			fmt.Printf("  '%s': %.4f\n", word, idf)
			count++
		} else {
			break
		}
	}
	fmt.Println()

	fmt.Println("================================================================================")
	fmt.Println("DIAGNOSIS COMPLETE")
	fmt.Println("================================================================================")
}
