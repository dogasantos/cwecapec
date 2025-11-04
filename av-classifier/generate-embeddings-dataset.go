package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

// -------------------- Data Structures --------------------

type CVEItem struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Published   string  `json:"published"`
	CVSS        float64 `json:"cvss"`
}

type CAPECInfo struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	LikelihoodOfAttack string   `json:"likelihood_of_attack"`
	TypicalSeverity    string   `json:"typical_severity"`
	Prerequisites      []string `json:"prerequisites"`
}

type EmbeddingRecord struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "CVE" or "CAPEC"
	Text      string    `json:"text"`
	Embedding []float64 `json:"embedding"`
	Metadata  Metadata  `json:"metadata"`
}

type Metadata struct {
	Name       string  `json:"name,omitempty"`
	Published  string  `json:"published,omitempty"`
	CVSS       float64 `json:"cvss,omitempty"`
	Severity   string  `json:"severity,omitempty"`
	Likelihood string  `json:"likelihood,omitempty"`
}

type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// -------------------- Main Program --------------------

func main() {
	fmt.Println("================================================================================")
	fmt.Println("EMBEDDINGS DATASET GENERATOR")
	fmt.Println("================================================================================")
	fmt.Println()

	// Check for OpenAI API key
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		fmt.Println("Error: OPENAI_API_KEY environment variable not set")
		os.Exit(1)
	}

	// Initialize OpenAI client
	client := openai.NewClient(option.WithAPIKey(apiKey))

	// Step 1: Load all CAPECs
	fmt.Println("[1/4] Loading CAPEC database...")
	capecs, err := loadCAPECs("resources/capec_db.json")
	if err != nil {
		fmt.Printf("Error loading CAPECs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Loaded %d CAPECs\n", len(capecs))

	// Step 2: Fetch all 2024 CVEs
	fmt.Println("\n[2/4] Fetching all 2024 CVEs from NVD...")
	cves, err := fetchAll2024CVEs()
	if err != nil {
		fmt.Printf("Error fetching CVEs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Fetched %d CVEs from 2024\n", len(cves))

	// Step 3: Generate embeddings
	fmt.Println("\n[3/4] Generating embeddings...")

	var allEmbeddings []EmbeddingRecord
	totalItems := len(cves) + len(capecs)
	processed := 0

	// Generate CAPEC embeddings
	fmt.Printf("\n  Processing CAPECs...\n")
	for id, capec := range capecs {
		text := fmt.Sprintf("%s: %s", capec.Name, capec.Description)

		embedding, err := getEmbedding(client, text)
		if err != nil {
			fmt.Printf("    Warning: Failed to generate embedding for CAPEC-%s: %v\n", id, err)
			continue
		}

		record := EmbeddingRecord{
			ID:        "CAPEC-" + id,
			Type:      "CAPEC",
			Text:      text,
			Embedding: embedding,
			Metadata: Metadata{
				Name:       capec.Name,
				Severity:   capec.TypicalSeverity,
				Likelihood: capec.LikelihoodOfAttack,
			},
		}
		allEmbeddings = append(allEmbeddings, record)

		processed++
		if processed%10 == 0 {
			fmt.Printf("    Progress: %d/%d (%.1f%%)\n", processed, totalItems, float64(processed)/float64(totalItems)*100)
		}

		// Rate limiting: OpenAI allows ~3000 RPM for embeddings
		time.Sleep(20 * time.Millisecond)
	}

	// Generate CVE embeddings
	fmt.Printf("\n  Processing CVEs...\n")
	for _, cve := range cves {
		embedding, err := getEmbedding(client, cve.Description)
		if err != nil {
			fmt.Printf("    Warning: Failed to generate embedding for %s: %v\n", cve.ID, err)
			continue
		}

		record := EmbeddingRecord{
			ID:        cve.ID,
			Type:      "CVE",
			Text:      cve.Description,
			Embedding: embedding,
			Metadata: Metadata{
				Published: cve.Published,
				CVSS:      cve.CVSS,
			},
		}
		allEmbeddings = append(allEmbeddings, record)

		processed++
		if processed%100 == 0 {
			fmt.Printf("    Progress: %d/%d (%.1f%%)\n", processed, totalItems, float64(processed)/float64(totalItems)*100)
		}

		// Rate limiting
		time.Sleep(20 * time.Millisecond)
	}

	fmt.Printf("\n  Total embeddings generated: %d\n", len(allEmbeddings))

	// Step 4: Save dataset
	fmt.Println("\n[4/4] Saving embeddings dataset...")

	outputFile := "resources/embeddings_dataset.json"
	if err := saveEmbeddings(allEmbeddings, outputFile); err != nil {
		fmt.Printf("Error saving dataset: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  Saved to: %s\n", outputFile)

	// Generate statistics
	fmt.Println("\n================================================================================")
	fmt.Println("DATASET STATISTICS")
	fmt.Println("================================================================================")
	fmt.Printf("Total records:     %d\n", len(allEmbeddings))

	cveCount := 0
	capecCount := 0
	for _, rec := range allEmbeddings {
		if rec.Type == "CVE" {
			cveCount++
		} else {
			capecCount++
		}
	}

	fmt.Printf("CVEs:              %d\n", cveCount)
	fmt.Printf("CAPECs:            %d\n", capecCount)
	fmt.Printf("Embedding dims:    %d\n", len(allEmbeddings[0].Embedding))

	// Calculate file size
	fileInfo, _ := os.Stat(outputFile)
	fmt.Printf("Dataset size:      %.2f MB\n", float64(fileInfo.Size())/(1024*1024))

	fmt.Println("\n[+] Embeddings dataset generated successfully!")
	fmt.Println()
}

// -------------------- Helper Functions --------------------

func loadCAPECs(filename string) (map[string]CAPECInfo, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var capecs map[string]CAPECInfo
	if err := json.Unmarshal(data, &capecs); err != nil {
		return nil, err
	}

	return capecs, nil
}

func fetchAll2024CVEs() ([]CVEItem, error) {
	const (
		baseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
		pubStartDate   = "2024-01-01T00:00:00.000"
		pubEndDate     = "2024-12-31T23:59:59.999"
		resultsPerPage = 2000
	)

	var allCVEs []CVEItem
	startIndex := 0

	for {
		url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=%d&startIndex=%d",
			baseURL, pubStartDate, pubEndDate, resultsPerPage, startIndex)

		fmt.Printf("  Fetching CVEs (offset %d)...\n", startIndex)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("NVD API error: %s - %s", resp.Status, string(body))
		}

		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			return nil, err
		}

		// Extract CVE data
		for _, vuln := range nvdResp.Vulnerabilities {
			cve := vuln.CVE

			// Get English description
			description := ""
			for _, desc := range cve.Descriptions {
				if desc.Lang == "en" {
					description = desc.Value
					break
				}
			}

			// Get CVSS score
			cvss := 0.0
			if len(cve.Metrics.CVSSMetricV31) > 0 {
				cvss = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			}

			allCVEs = append(allCVEs, CVEItem{
				ID:          cve.ID,
				Description: description,
				Published:   cve.Published,
				CVSS:        cvss,
			})
		}

		// Check if we've fetched all results
		if startIndex+resultsPerPage >= nvdResp.TotalResults {
			break
		}

		startIndex += resultsPerPage

		// Rate limiting: NVD allows 5 requests per 30 seconds without API key
		time.Sleep(6 * time.Second)
	}

	return allCVEs, nil
}

func getEmbedding(client *openai.Client, text string) ([]float64, error) {
	// Clean text
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("empty text")
	}

	// Truncate if too long (OpenAI has 8191 token limit)
	if len(text) > 30000 {
		text = text[:30000]
	}

	ctx := context.Background()

	resp, err := client.Embeddings.New(ctx, openai.EmbeddingNewParams{
		Input: openai.F[openai.EmbeddingNewParamsInputUnion](
			openai.EmbeddingNewParamsInputArrayOfStrings([]string{text}),
		),
		Model: openai.F(openai.EmbeddingModelTextEmbedding3Small),
	})

	if err != nil {
		return nil, err
	}

	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("no embedding returned")
	}

	return resp.Data[0].Embedding, nil
}

func saveEmbeddings(embeddings []EmbeddingRecord, filename string) error {
	data, err := json.MarshalIndent(embeddings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
