package main

import (
	"compress/gzip"
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

type Progress struct {
	ProcessedIDs map[string]bool `json:"processed_ids"`
	TotalCount   int             `json:"total_count"`
}

// NVD Feed structures
type NVDFeed struct {
	CVEItems []struct {
		CVE struct {
			CVEDataMeta struct {
				ID string `json:"ID"`
			} `json:"CVE_data_meta"`
			Description struct {
				DescriptionData []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
		} `json:"cve"`
		PublishedDate string `json:"publishedDate"`
		Impact        struct {
			BaseMetricV3 struct {
				CVSSV3 struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssV3"`
			} `json:"baseMetricV3"`
		} `json:"impact"`
	} `json:"CVE_Items"`
}

// -------------------- Main Program --------------------

func main() {
	fmt.Println("================================================================================")
	fmt.Println("EMBEDDINGS DATASET GENERATOR v3 (Memory-Efficient + Resumable)")
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

	outputFile := "resources/embeddings_dataset.json"
	progressFile := "resources/embeddings_progress.json"

	// Load progress if exists
	progress := loadProgress(progressFile)
	fmt.Printf("Loaded progress: %d items already processed\n\n", len(progress.ProcessedIDs))

	// Open output file for appending
	file, err := openOutputFile(outputFile, len(progress.ProcessedIDs) == 0)
	if err != nil {
		fmt.Printf("Error opening output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Step 1: Load all CAPECs
	fmt.Println("[1/4] Loading CAPEC database...")
	capecs, err := loadCAPECs("resources/capec_db.json")
	if err != nil {
		fmt.Printf("Error loading CAPECs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Loaded %d CAPECs\n", len(capecs))

	// Step 2: Load CVEs
	fmt.Println("\n[2/4] Loading CVE data...")

	var cves []CVEItem

	// Try to load from training_data.json first
	if _, err := os.Stat("resources/training_data.json"); err == nil {
		fmt.Println("  Found local training_data.json, loading...")
		cves, err = loadCVEsFromTrainingData("resources/training_data.json")
		if err != nil {
			fmt.Printf("  Warning: Failed to load training_data.json: %v\n", err)
		} else {
			fmt.Printf("  Loaded %d CVEs from training_data.json\n", len(cves))
		}
	}

	// If no local data, download from NVD feed
	if len(cves) == 0 {
		fmt.Println("  Downloading 2024 CVEs from NVD feed...")
		cves, err = downloadCVEsFromFeed(2024)
		if err != nil {
			fmt.Printf("Error downloading CVEs: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Downloaded %d CVEs from 2024\n", len(cves))
	}

	totalItems := len(cves) + len(capecs)
	processed := len(progress.ProcessedIDs)

	// Step 3: Generate embeddings (incrementally)
	fmt.Println("\n[3/4] Generating embeddings...")
	fmt.Printf("  Total items: %d\n", totalItems)
	fmt.Printf("  Already processed: %d\n", processed)
	fmt.Printf("  Remaining: %d\n\n", totalItems-processed)

	// Process CAPECs
	fmt.Printf("  Processing CAPECs...\n")
	for id, capec := range capecs {
		capecID := "CAPEC-" + id

		// Skip if already processed
		if progress.ProcessedIDs[capecID] {
			continue
		}

		text := fmt.Sprintf("%s: %s", capec.Name, capec.Description)

		embedding, err := getEmbedding(&client, text)
		if err != nil {
			fmt.Printf("    Warning: Failed to generate embedding for %s: %v\n", capecID, err)
			continue
		}

		record := EmbeddingRecord{
			ID:        capecID,
			Type:      "CAPEC",
			Text:      text,
			Embedding: embedding,
			Metadata: Metadata{
				Name:       capec.Name,
				Severity:   capec.TypicalSeverity,
				Likelihood: capec.LikelihoodOfAttack,
			},
		}

		// Write immediately to file
		if err := writeRecord(file, record, processed == 0); err != nil {
			fmt.Printf("    Error writing record: %v\n", err)
			continue
		}

		// Update progress
		progress.ProcessedIDs[capecID] = true
		processed++

		if processed%10 == 0 {
			fmt.Printf("    Progress: %d/%d (%.1f%%)\n", processed, totalItems, float64(processed)/float64(totalItems)*100)
			// Save progress periodically
			saveProgress(progress, progressFile)
		}

		// Rate limiting
		time.Sleep(20 * time.Millisecond)
	}

	// Process CVEs
	fmt.Printf("\n  Processing CVEs...\n")
	for _, cve := range cves {
		// Skip if already processed
		if progress.ProcessedIDs[cve.ID] {
			continue
		}

		embedding, err := getEmbedding(&client, cve.Description)
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

		// Write immediately to file
		if err := writeRecord(file, record, false); err != nil {
			fmt.Printf("    Error writing record: %v\n", err)
			continue
		}

		// Update progress
		progress.ProcessedIDs[cve.ID] = true
		processed++

		if processed%100 == 0 {
			fmt.Printf("    Progress: %d/%d (%.1f%%)\n", processed, totalItems, float64(processed)/float64(totalItems)*100)
			// Save progress periodically
			saveProgress(progress, progressFile)
		}

		// Rate limiting
		time.Sleep(20 * time.Millisecond)
	}

	// Close JSON array
	file.WriteString("\n]\n")

	// Save final progress
	progress.TotalCount = processed
	saveProgress(progress, progressFile)

	fmt.Printf("\n  Total embeddings generated: %d\n", processed)

	// Step 4: Statistics
	fmt.Println("\n[4/4] Generation complete!")

	fileInfo, _ := os.Stat(outputFile)
	fmt.Printf("  Output file: %s\n", outputFile)
	fmt.Printf("  File size: %.2f MB\n", float64(fileInfo.Size())/(1024*1024))

	fmt.Println("\n================================================================================")
	fmt.Println("[+] Embeddings dataset generated successfully!")
	fmt.Println("    You can safely delete: resources/embeddings_progress.json")
	fmt.Println("================================================================================")
	fmt.Println()
}

// -------------------- Helper Functions --------------------

func loadProgress(filename string) Progress {
	progress := Progress{
		ProcessedIDs: make(map[string]bool),
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return progress // File doesn't exist, start fresh
	}

	json.Unmarshal(data, &progress)
	return progress
}

func saveProgress(progress Progress, filename string) error {
	data, err := json.MarshalIndent(progress, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func openOutputFile(filename string, isNew bool) (*os.File, error) {
	if isNew {
		// Create new file and write JSON array opening
		file, err := os.Create(filename)
		if err != nil {
			return nil, err
		}
		file.WriteString("[\n")
		return file, nil
	} else {
		// Append to existing file
		// Remove the closing ']' and append
		file, err := os.OpenFile(filename, os.O_RDWR, 0644)
		if err != nil {
			return nil, err
		}

		// Seek to end and remove last ']'
		info, _ := file.Stat()
		if info.Size() > 2 {
			file.Seek(-2, io.SeekEnd) // Remove '\n]'
			file.WriteString(",\n")
		}

		return file, nil
	}
}

func writeRecord(file *os.File, record EmbeddingRecord, isFirst bool) error {
	data, err := json.MarshalIndent(record, "  ", "  ")
	if err != nil {
		return err
	}

	if !isFirst {
		file.WriteString(",\n")
	}
	file.WriteString("  ")
	file.Write(data)

	return nil
}

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

func loadCVEsFromTrainingData(filename string) ([]CVEItem, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Try to parse as array of CVEItem first
	var cves []CVEItem
	if err := json.Unmarshal(data, &cves); err == nil {
		return cves, nil
	}

	// If that fails, try to parse as map[string]CVEItem
	var cveMap map[string]CVEItem
	if err := json.Unmarshal(data, &cveMap); err == nil {
		cves = make([]CVEItem, 0, len(cveMap))
		for _, cve := range cveMap {
			cves = append(cves, cve)
		}
		return cves, nil
	}

	return nil, fmt.Errorf("unable to parse training_data.json")
}

func downloadCVEsFromFeed(year int) ([]CVEItem, error) {
	feedURL := fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)

	fmt.Printf("  Downloading from: %s\n", feedURL)

	resp, err := http.Get(feedURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	var feed NVDFeed
	if err := json.NewDecoder(gzReader).Decode(&feed); err != nil {
		return nil, err
	}

	var cves []CVEItem
	for _, item := range feed.CVEItems {
		description := ""
		for _, desc := range item.CVE.Description.DescriptionData {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		cves = append(cves, CVEItem{
			ID:          item.CVE.CVEDataMeta.ID,
			Description: description,
			Published:   item.PublishedDate,
			CVSS:        item.Impact.BaseMetricV3.CVSSV3.BaseScore,
		})
	}

	return cves, nil
}

func getEmbedding(client *openai.Client, text string) ([]float64, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("empty text")
	}

	if len(text) > 30000 {
		text = text[:30000]
	}

	ctx := context.Background()

	resp, err := client.Embeddings.New(ctx, openai.EmbeddingNewParams{
		Input: openai.EmbeddingNewParamsInputUnion{
			OfString: openai.String(text),
		},
		Model: openai.EmbeddingModelTextEmbedding3Small,
	})

	if err != nil {
		return nil, err
	}

	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("no embedding returned")
	}

	return resp.Data[0].Embedding, nil
}
