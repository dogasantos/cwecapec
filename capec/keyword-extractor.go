package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type CAPECData struct {
	CAPECID     string `json:"capec_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type KeywordScore struct {
	Keyword     string
	Score       float64
	Exclusivity float64
	InCAPECs    int
}

func main() {
	// Load CAPEC data
	data, err := os.ReadFile("capec_training_data.json")
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	var capecs []CAPECData
	if err := json.Unmarshal(data, &capecs); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Analyzing %d CAPECs for exclusive keywords...\n\n", len(capecs))

	// Step 1: Extract technical terms from CAPEC names and descriptions
	capecTerms := make(map[string]map[string]bool) // capecID -> set of terms
	termCAPECs := make(map[string][]string)        // term -> list of CAPEC IDs

	for _, capec := range capecs {
		// Prioritize name over description
		nameTerms := extractTechnicalTerms(capec.Name, true)
		descTerms := extractTechnicalTerms(capec.Description, false)

		allTerms := append(nameTerms, descTerms...)

		capecTerms[capec.CAPECID] = make(map[string]bool)
		for _, term := range allTerms {
			if !capecTerms[capec.CAPECID][term] {
				capecTerms[capec.CAPECID][term] = true
				termCAPECs[term] = append(termCAPECs[term], capec.CAPECID)
			}
		}
	}

	// Step 2: For each CAPEC, select the most exclusive keywords
	exclusiveKeywords := make(map[string][]KeywordScore)

	for _, capec := range capecs {
		var scored []KeywordScore

		// Score each term by exclusivity and quality
		for term := range capecTerms[capec.CAPECID] {
			capecCount := len(termCAPECs[term])

			// Skip terms that appear in too many CAPECs
			if capecCount > 10 {
				continue
			}

			// Exclusivity score
			exclusivity := 1.0 / float64(capecCount)

			// Quality score based on term characteristics
			quality := scoreTermQuality(term, capec.Name)

			// Combined score
			score := exclusivity * quality

			scored = append(scored, KeywordScore{
				Keyword:     term,
				Score:       score,
				Exclusivity: exclusivity,
				InCAPECs:    capecCount,
			})
		}

		// Sort by score descending
		sort.Slice(scored, func(i, j int) bool {
			return scored[i].Score > scored[j].Score
		})

		// Take top keywords (max 8, prefer unique ones)
		maxKeywords := 8
		var selected []KeywordScore
		for _, kw := range scored {
			if len(selected) >= maxKeywords {
				break
			}
			// Only include if appears in <=5 CAPECs
			if kw.InCAPECs <= 5 {
				selected = append(selected, kw)
			}
		}

		if len(selected) > 0 {
			exclusiveKeywords[capec.CAPECID] = selected
		}
	}

	// Step 3: Output as Go map
	fmt.Println("var attackKeywords = map[string][]string{")

	// Sort by CAPEC ID numerically
	var capecIDs []string
	for id := range exclusiveKeywords {
		capecIDs = append(capecIDs, id)
	}
	sort.Slice(capecIDs, func(i, j int) bool {
		var a, b int
		fmt.Sscanf(capecIDs[i], "%d", &a)
		fmt.Sscanf(capecIDs[j], "%d", &b)
		return a < b
	})

	for _, capecID := range capecIDs {
		keywords := exclusiveKeywords[capecID]

		// Find the CAPEC name
		var name string
		for _, capec := range capecs {
			if capec.CAPECID == capecID {
				name = capec.Name
				break
			}
		}

		fmt.Printf("\t\"%s\": {", capecID)
		for i, kw := range keywords {
			fmt.Printf("\"%s\"", kw.Keyword)
			if i < len(keywords)-1 {
				fmt.Print(", ")
			}
		}
		fmt.Printf("}, // %s\n", name)
	}

	fmt.Println("}")

	fmt.Fprintf(os.Stderr, "\n\nStatistics:\n")
	fmt.Fprintf(os.Stderr, "Total CAPECs: %d\n", len(capecs))
	fmt.Fprintf(os.Stderr, "CAPECs with exclusive keywords: %d (%.1f%%)\n",
		len(exclusiveKeywords),
		float64(len(exclusiveKeywords))/float64(len(capecs))*100)
}

func extractTechnicalTerms(text string, isName bool) []string {
	text = strings.ToLower(text)

	// Remove special characters but keep hyphens and slashes
	reg := regexp.MustCompile(`[^a-z0-9\s\-/]`)
	text = reg.ReplaceAllString(text, " ")

	words := strings.Fields(text)

	var terms []string
	seen := make(map[string]bool)

	// Extract 1-3 word technical phrases
	for i := 0; i < len(words); i++ {
		word := words[i]

		// Skip very short or common words
		if len(word) < 3 || isCommonWord(word) {
			continue
		}

		// Single word (if technical)
		if isTechnicalWord(word) && !seen[word] {
			terms = append(terms, word)
			seen[word] = true
		}

		// 2-word phrase
		if i < len(words)-1 && !isCommonWord(words[i+1]) {
			phrase := word + " " + words[i+1]
			if !seen[phrase] && len(phrase) <= 30 {
				// Boost score if from name
				if isName || isTechnicalPhrase(phrase) {
					terms = append(terms, phrase)
					seen[phrase] = true
				}
			}
		}

		// 3-word phrase (only if very technical or from name)
		if i < len(words)-2 && (isName || isTechnicalWord(word)) {
			if !isCommonWord(words[i+1]) && !isCommonWord(words[i+2]) {
				phrase := word + " " + words[i+1] + " " + words[i+2]
				if !seen[phrase] && len(phrase) <= 40 {
					terms = append(terms, phrase)
					seen[phrase] = true
				}
			}
		}
	}

	return terms
}

func scoreTermQuality(term string, capecName string) float64 {
	score := 1.0

	// Boost if term appears in CAPEC name
	if strings.Contains(strings.ToLower(capecName), term) {
		score *= 3.0
	}

	// Boost technical terms
	if isTechnicalWord(term) {
		score *= 1.5
	}

	// Prefer shorter terms (easier to match)
	wordCount := len(strings.Fields(term))
	if wordCount == 1 {
		score *= 1.2
	} else if wordCount == 2 {
		score *= 1.5
	} else if wordCount == 3 {
		score *= 1.0
	} else {
		score *= 0.5 // Penalize long phrases
	}

	// Boost terms with specific patterns
	if strings.Contains(term, "injection") ||
		strings.Contains(term, "overflow") ||
		strings.Contains(term, "bypass") ||
		strings.Contains(term, "spoofing") ||
		strings.Contains(term, "hijacking") ||
		strings.Contains(term, "traversal") {
		score *= 1.3
	}

	return score
}

func isTechnicalWord(word string) bool {
	// Check for technical patterns
	technical := map[string]bool{
		// Protocols
		"http": true, "https": true, "ftp": true, "smtp": true, "dns": true,
		"ldap": true, "soap": true, "xml": true, "json": true, "sql": true,
		"tcp": true, "udp": true, "icmp": true, "dhcp": true, "ssl": true,
		"tls": true, "ssh": true, "rmi": true, "jndi": true,

		// Attack types
		"xss": true, "csrf": true, "ssrf": true, "xxe": true, "sqli": true,
		"injection": true, "overflow": true, "traversal": true, "bypass": true,
		"spoofing": true, "hijacking": true, "poisoning": true, "flooding": true,
		"sniffing": true, "sidejacking": true, "clickjacking": true,

		// Technical terms
		"buffer": true, "heap": true, "stack": true, "pointer": true,
		"integer": true, "cookie": true, "session": true, "token": true,
		"authentication": true, "authorization": true, "deserialization": true,
		"serialization": true, "encoding": true, "decoding": true,
		"encryption": true, "decryption": true, "hashing": true,
		"checksum": true, "signature": true, "certificate": true,
		"parameter": true, "header": true, "payload": true, "request": true,
		"response": true, "query": true, "command": true, "script": true,
		"code": true, "executable": true, "binary": true, "firmware": true,
		"metadata": true, "schema": true, "namespace": true, "dom": true,
		"xpath": true, "regex": true, "unicode": true, "utf": true,
		"ascii": true, "base64": true, "url": true, "uri": true,
	}

	return technical[word]
}

func isTechnicalPhrase(phrase string) bool {
	// Check if phrase contains at least one technical word
	words := strings.Fields(phrase)
	for _, word := range words {
		if isTechnicalWord(word) {
			return true
		}
	}
	return false
}

func isCommonWord(word string) bool {
	common := map[string]bool{
		"the": true, "and": true, "for": true, "are": true, "but": true,
		"not": true, "you": true, "all": true, "can": true, "her": true,
		"was": true, "one": true, "our": true, "out": true, "day": true,
		"get": true, "has": true, "him": true, "his": true, "how": true,
		"man": true, "new": true, "now": true, "old": true, "see": true,
		"two": true, "way": true, "who": true, "boy": true, "did": true,
		"its": true, "let": true, "put": true, "say": true, "she": true,
		"too": true, "use": true, "this": true, "that": true, "with": true,
		"from": true, "have": true, "they": true, "will": true, "what": true,
		"been": true, "more": true, "when": true, "your": true, "said": true,
		"each": true, "which": true, "their": true, "time": true,
		"about": true, "many": true, "then": true, "them": true, "these": true,
		"some": true, "would": true, "make": true, "like": true, "into": true,
		"could": true, "other": true, "than": true, "first": true,
		"called": true, "where": true, "after": true, "back": true, "just": true,
		"name": true, "much": true, "through": true, "also": true, "around": true,
		"another": true, "came": true, "come": true, "work": true, "three": true,
		"must": true, "because": true, "does": true, "part": true, "even": true,
		"place": true, "well": true, "such": true, "here": true, "take": true,
		"why": true, "help": true, "different": true, "away": true,
		"again": true, "off": true, "went": true, "tell": true, "number": true,
		"may": true, "used": true, "allows": true, "allow": true, "using": true,
		"attacker": true, "attack": true, "exploit": true, "vulnerability": true,
		"application": true, "system": true, "user": true, "data": true,
		"information": true, "access": true, "control": true, "security": true,
		"adversary": true, "target": true, "victim": true, "malicious": true,
		"cause": true, "result": true, "order": true, "able": true,
	}
	return common[word]
}
