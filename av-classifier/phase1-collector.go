package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// ============================================================================
// ESTRUTURAS DE DADOS - NVD FEED (ENTRADA)
// ============================================================================
// Estas estruturas mapeiam o formato JSON 2.0 do NVD (National Vulnerability Database)
// ============================================================================

// NVDFeed representa o feed completo de vulnerabilidades do NVD
type NVDFeed struct {
	ResultsPerPage  int             `json:"resultsPerPage"`  // Número de resultados por página
	StartIndex      int             `json:"startIndex"`      // Índice inicial dos resultados
	TotalResults    int             `json:"totalResults"`    // Total de resultados disponíveis
	Format          string          `json:"format"`          // Formato do feed (ex: "NVD_CVE")
	Version         string          `json:"version"`         // Versão do formato (ex: "2.0")
	Timestamp       string          `json:"timestamp"`       // Timestamp da geração do feed
	Vulnerabilities []Vulnerability `json:"vulnerabilities"` // Lista de vulnerabilidades
}

// Vulnerability representa uma vulnerabilidade individual no feed
type Vulnerability struct {
	CVE CVEData `json:"cve"` // Dados do CVE
}

// CVEData contém os dados principais de um CVE
type CVEData struct {
	ID           string        `json:"id"`           // ID do CVE (ex: "CVE-2024-12345")
	Descriptions []Description `json:"descriptions"` // Descrições em múltiplos idiomas
	Published    string        `json:"published"`    // Data de publicação (ISO 8601)
	Weaknesses   []Weakness    `json:"weaknesses"`   // Lista de CWEs associados
}

// Description representa uma descrição textual em um idioma específico
type Description struct {
	Lang  string `json:"lang"`  // Código do idioma (ex: "en", "es")
	Value string `json:"value"` // Texto da descrição
}

// Weakness representa uma fraqueza (CWE) associada ao CVE
type Weakness struct {
	Description []WeaknessDesc `json:"description"` // Descrições da fraqueza
}

// WeaknessDesc contém a descrição de uma fraqueza em um idioma
type WeaknessDesc struct {
	Lang  string `json:"lang"`  // Código do idioma
	Value string `json:"value"` // Valor do CWE (ex: "CWE-79")
}

// ============================================================================
// ESTRUTURAS DE DADOS - TRAINING DATA (SAÍDA)
// ============================================================================

// TrainingRecord representa um registro de treinamento processado
type TrainingRecord struct {
	CVEID         string   `json:"cve_id"`         // ID do CVE
	Description   string   `json:"description"`    // Descrição em inglês
	CWEs          []string `json:"cwes"`           // Lista de IDs de CWE (ex: ["79", "89"])
	AttackVectors []string `json:"attack_vectors"` // Vetores de ataque mapeados
	PublishedDate string   `json:"published_date"` // Data de publicação
}

// ============================================================================
// ESTRUTURAS DE DADOS - MAPEAMENTO DE VETORES DE ATAQUE
// ============================================================================

// AttackVectorMapping define o mapeamento de CWEs para um vetor de ataque
type AttackVectorMapping struct {
	Name        string   // Nome do vetor de ataque (ex: "sql_injection")
	CWEs        []string // Lista de IDs de CWE associados
	Description string   // Descrição legível do vetor
	Priority    int      // Prioridade (1=Crítico, 2=Alto, 3=Médio)
}

// ============================================================================
// MAPEAMENTO DE VETORES DE ATAQUE
// ============================================================================
// Define 35 vetores de ataque organizados em 3 níveis de prioridade
// ============================================================================

var attackVectorMappings = []AttackVectorMapping{
	// ========================================================================
	// TIER 1: CRÍTICO (10 vetores)
	// Vulnerabilidades de maior impacto e mais exploradas
	// ========================================================================
	{Name: "xss", CWEs: []string{"79", "80", "83"}, Description: "Cross-Site Scripting", Priority: 1},
	{Name: "sql_injection", CWEs: []string{"89"}, Description: "SQL Injection", Priority: 1},
	{Name: "rce", CWEs: []string{"94", "95"}, Description: "Remote Code Execution", Priority: 1},
	{Name: "command_injection", CWEs: []string{"77", "78"}, Description: "OS Command Injection", Priority: 1},
	{Name: "path_traversal", CWEs: []string{"22", "23", "36"}, Description: "Path Traversal", Priority: 1},
	{Name: "ssrf", CWEs: []string{"918"}, Description: "Server-Side Request Forgery", Priority: 1},
	{Name: "deserialization", CWEs: []string{"502"}, Description: "Deserialization Vulnerabilities", Priority: 1},
	{Name: "auth_bypass", CWEs: []string{"287", "288", "290", "302", "306"}, Description: "Authentication Bypass", Priority: 1},
	{Name: "authz_bypass", CWEs: []string{"285", "639"}, Description: "Authorization Bypass", Priority: 1},
	{Name: "file_upload", CWEs: []string{"434"}, Description: "File Upload Vulnerabilities", Priority: 1},

	// ========================================================================
	// TIER 2: ALTA PRIORIDADE (10 vetores)
	// Vulnerabilidades de alto impacto mas menos comuns
	// ========================================================================
	{Name: "csrf", CWEs: []string{"352"}, Description: "Cross-Site Request Forgery", Priority: 2},
	{Name: "xxe", CWEs: []string{"611"}, Description: "XML External Entity", Priority: 2},
	{Name: "ldap_injection", CWEs: []string{"90"}, Description: "LDAP Injection", Priority: 2},
	{Name: "jndi_injection", CWEs: []string{"917"}, Description: "JNDI/Expression Language Injection", Priority: 2},
	{Name: "privilege_escalation", CWEs: []string{"269", "274", "266", "250"}, Description: "Privilege Escalation", Priority: 2},
	{Name: "buffer_overflow", CWEs: []string{"119", "120", "121", "122", "787", "788"}, Description: "Buffer Overflow", Priority: 2},
	{Name: "idor", CWEs: []string{"639", "284"}, Description: "Insecure Direct Object Reference", Priority: 2},
	{Name: "http_desync", CWEs: []string{"444"}, Description: "HTTP Request Smuggling", Priority: 2},
	{Name: "hardcoded_credentials", CWEs: []string{"798", "259", "321"}, Description: "Hard-coded Credentials", Priority: 2},
	{Name: "info_disclosure", CWEs: []string{"200", "209", "213", "215", "532"}, Description: "Information Disclosure", Priority: 2},

	// ========================================================================
	// TIER 3: PRIORIDADE MÉDIA (15 vetores)
	// Vulnerabilidades importantes mas de menor impacto imediato
	// ========================================================================
	{Name: "dos", CWEs: []string{"400", "770", "400", "835", "674"}, Description: "Denial of Service", Priority: 3},
	{Name: "nosql_injection", CWEs: []string{"943"}, Description: "NoSQL Injection", Priority: 3},
	{Name: "xpath_injection", CWEs: []string{"643"}, Description: "XPath Injection", Priority: 3},
	{Name: "open_redirect", CWEs: []string{"601"}, Description: "Open Redirect", Priority: 3},
	{Name: "session_fixation", CWEs: []string{"384"}, Description: "Session Fixation", Priority: 3},
	{Name: "crypto_failure", CWEs: []string{"327", "328", "329", "326"}, Description: "Cryptographic Failures", Priority: 3},
	{Name: "integer_overflow", CWEs: []string{"190", "191"}, Description: "Integer Overflow", Priority: 3},
	{Name: "use_after_free", CWEs: []string{"416"}, Description: "Use After Free", Priority: 3},
	{Name: "null_pointer", CWEs: []string{"476"}, Description: "NULL Pointer Dereference", Priority: 3},
	{Name: "format_string", CWEs: []string{"134"}, Description: "Format String Vulnerability", Priority: 3},
	{Name: "email_injection", CWEs: []string{"93"}, Description: "Email Header Injection", Priority: 3},
	{Name: "race_condition", CWEs: []string{"362", "366", "367"}, Description: "Race Condition", Priority: 3},
	{Name: "ssti", CWEs: []string{"1336"}, Description: "Server-Side Template Injection", Priority: 3},
	{Name: "input_validation", CWEs: []string{"20", "1284"}, Description: "Improper Input Validation", Priority: 3},
	{Name: "code_injection", CWEs: []string{"94", "95"}, Description: "Code Injection", Priority: 3},
}

// ============================================================================
// FUNÇÕES DE MAPEAMENTO
// ============================================================================

/*
 * Função: buildCWEMap
 * Descrição: Constrói um mapa reverso de CWE ID para vetores de ataque
 * Objetivo: Permitir consulta rápida O(1) de quais vetores de ataque estão
 *           associados a um CWE específico
 * Como faz: 1. Cria um mapa vazio de CWE ID → lista de vetores
 *           2. Itera por todos os mapeamentos de vetores de ataque
 *           3. Para cada CWE em cada mapeamento:
 *              a. Adiciona o nome do vetor à lista do CWE
 *           4. Retorna o mapa completo
 * Input: Nenhum (usa a variável global attackVectorMappings)
 * Output: map[string][]string - Mapa de CWE ID para lista de vetores de ataque
 *         Exemplo: {"79": ["xss"], "89": ["sql_injection"]}
 * Por que faz: O mapeamento direto (vetor → CWEs) é útil para definição,
 *              mas o mapeamento reverso (CWE → vetores) é necessário para
 *              classificação. Quando processamos um CVE com CWE-79, precisamos
 *              saber rapidamente que ele mapeia para "xss".
 */
func buildCWEMap() map[string][]string {
	cweMap := make(map[string][]string)
	for _, mapping := range attackVectorMappings {
		for _, cwe := range mapping.CWEs {
			cweMap[cwe] = append(cweMap[cwe], mapping.Name)
		}
	}
	return cweMap
}

// ============================================================================
// FUNÇÕES DE DOWNLOAD E PARSING
// ============================================================================

/*
 * Função: downloadFeed
 * Descrição: Baixa e descomprime um feed do NVD no formato JSON gzipado
 * Objetivo: Obter os dados de vulnerabilidades do NVD para processamento
 * Como faz: 1. Faz requisição HTTP GET para o URL do feed
 *           2. Verifica se a resposta é HTTP 200 (sucesso)
 *           3. Cria um leitor gzip para descomprimir o conteúdo
 *           4. Parseia o JSON descomprimido diretamente em memória
 *           5. Retorna a estrutura NVDFeed parseada
 * Input: url (string) - URL do feed NVD (ex: nvdcve-2.0-2024.json.gz)
 * Output: (*NVDFeed, error) - Feed parseado ou erro
 * Por que faz: O NVD distribui feeds anuais em formato JSON gzipado.
 *              Esta função encapsula todo o processo de download, descompressão
 *              e parsing, tratando erros em cada etapa.
 */
func downloadFeed(url string) (*NVDFeed, error) {
	fmt.Printf("  Downloading: %s\n", url)

	// Fazer requisição HTTP GET
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	// Verificar código de status HTTP
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Descomprimir gzip
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip decompression failed: %w", err)
	}
	defer gzReader.Close()

	// Parsear JSON diretamente do stream descomprimido
	var feed NVDFeed
	if err := json.NewDecoder(gzReader).Decode(&feed); err != nil {
		return nil, fmt.Errorf("JSON parsing failed: %w", err)
	}

	fmt.Printf("  Loaded %d vulnerabilities\n", len(feed.Vulnerabilities))

	return &feed, nil
}

// ============================================================================
// FUNÇÕES DE EXTRAÇÃO E MAPEAMENTO
// ============================================================================

/*
 * Função: extractCWEs
 * Descrição: Extrai os IDs de CWE de uma vulnerabilidade do NVD
 * Objetivo: Obter a lista de CWEs associados a um CVE para mapeamento
 * Como faz: 1. Itera por todas as fraquezas (weaknesses) do CVE
 *           2. Para cada descrição de fraqueza:
 *              a. Verifica se começa com "CWE-"
 *              b. Remove o prefixo "CWE-" para obter apenas o número
 *              c. Adiciona à lista de CWEs
 *           3. Retorna a lista completa
 * Input: vuln (Vulnerability) - Vulnerabilidade do feed NVD
 * Output: []string - Lista de IDs de CWE (ex: ["79", "89"])
 * Por que faz: O NVD armazena CWEs no formato "CWE-79", mas nosso mapeamento
 *              usa apenas o número ("79"). Esta função normaliza o formato.
 */
func extractCWEs(vuln Vulnerability) []string {
	var cwes []string
	for _, weakness := range vuln.CVE.Weaknesses {
		for _, desc := range weakness.Description {
			// Extrair número do CWE do formato "CWE-XXX"
			if strings.HasPrefix(desc.Value, "CWE-") {
				cweNum := strings.TrimPrefix(desc.Value, "CWE-")
				cwes = append(cwes, cweNum)
			}
		}
	}
	return cwes
}

/*
 * Função: mapToAttackVectors
 * Descrição: Mapeia uma lista de CWEs para seus vetores de ataque correspondentes
 * Objetivo: Converter CWEs em vetores de ataque para treinamento do classificador
 * Como faz: 1. Cria um conjunto (map) para evitar duplicatas
 *           2. Para cada CWE na lista:
 *              a. Busca no mapa CWE → vetores
 *              b. Se encontrado, adiciona todos os vetores ao conjunto
 *           3. Converte o conjunto para slice
 *           4. Retorna a lista de vetores únicos
 * Input: cwes ([]string) - Lista de IDs de CWE
 *        cweMap (map[string][]string) - Mapa de CWE para vetores
 * Output: []string - Lista de vetores de ataque únicos
 * Por que faz: Um CVE pode ter múltiplos CWEs, e cada CWE pode mapear para
 *              múltiplos vetores. Esta função consolida tudo em uma lista
 *              única de vetores, removendo duplicatas.
 */
func mapToAttackVectors(cwes []string, cweMap map[string][]string) []string {
	// Usar conjunto para evitar duplicatas
	vectorSet := make(map[string]bool)
	for _, cwe := range cwes {
		if vectors, ok := cweMap[cwe]; ok {
			for _, v := range vectors {
				vectorSet[v] = true
			}
		}
	}

	// Converter conjunto para slice
	var vectors []string
	for v := range vectorSet {
		vectors = append(vectors, v)
	}
	return vectors
}

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

/*
 * Função: main
 * Descrição: Ponto de entrada do programa que orquestra a coleta e preparação
 *            dos dados de treinamento a partir do feed NVD
 * Objetivo: Criar um dataset de treinamento (training_data.json) contendo CVEs
 *           com suas descrições, CWEs e vetores de ataque mapeados, pronto para
 *           uso no treinamento do modelo Naive Bayes
 * Como faz: 1. Configura parâmetros (ano, arquivo de saída)
 *           2. Constrói o mapa reverso de CWE → vetores
 *           3. Baixa o feed NVD do ano especificado (tenta formato 2.0, depois 1.1)
 *           4. Processa cada vulnerabilidade:
 *              a. Extrai descrição em inglês
 *              b. Extrai CWEs
 *              c. Mapeia CWEs para vetores de ataque
 *              d. Cria registro de treinamento se houver vetores
 *           5. Salva todos os registros em JSON formatado
 *           6. Exibe estatísticas:
 *              a. Total de CVEs processados
 *              b. CVEs com vetores de ataque
 *              c. Distribuição de vetores de ataque
 * Input: Nenhum (configuração hardcoded: ano 2024)
 * Output: Arquivo resources/training_data.json contendo:
 *         - Lista de registros de treinamento
 *         - Cada registro com: CVE ID, descrição, CWEs, vetores, data
 *         Estatísticas no console
 * Por que faz: Esta é a Fase 1 da pipeline de treinamento. Sem dados de
 *              treinamento de qualidade, não é possível treinar o modelo
 *              Naive Bayes. Esta função:
 *              - Automatiza a coleta de dados do NVD
 *              - Filtra CVEs sem CWEs ou vetores mapeados
 *              - Cria um dataset limpo e estruturado
 *              - Fornece visibilidade da distribuição de dados
 */
func main() {
	fmt.Println("=================================================================")
	fmt.Println("Phase 1: NVD Feed Collection & Preparation for Naive Bayes")
	fmt.Println("=================================================================\n")

	// Configuração
	year := 2024
	outputFile := "resources/training_data.json"

	// URL do feed JSON 2.0 do NVD
	feedURL := fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)

	// Tentar formato 2.0 primeiro
	feedURL = fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz", year)

	// Construir mapeamento de CWE
	cweMap := buildCWEMap()
	fmt.Printf("Loaded %d attack vector categories\n", len(attackVectorMappings))
	fmt.Printf("Mapped %d unique CWE IDs\n\n", len(cweMap))

	fmt.Printf("Downloading NVD feed for year %d...\n", year)

	// Baixar feed
	feed, err := downloadFeed(feedURL)
	if err != nil {
		fmt.Printf("Error downloading feed: %v\n", err)
		fmt.Println("\nTrying alternative URL format...")

		// Tentar URL alternativo (formato 1.1)
		feedURL = fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)
		feed, err = downloadFeed(feedURL)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("\nProcessing vulnerabilities...")

	// Processar vulnerabilidades
	var trainingData []TrainingRecord
	totalProcessed := 0
	totalWithVectors := 0

	for i, vuln := range feed.Vulnerabilities {
		totalProcessed++

		// Exibir progresso a cada 1000 CVEs
		if (i+1)%1000 == 0 {
			fmt.Printf("  Processed %d/%d CVEs (%d with attack vectors)\n", i+1, len(feed.Vulnerabilities), totalWithVectors)
		}

		// Extrair descrição em inglês
		var description string
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		// Pular se não houver descrição em inglês
		if description == "" {
			continue
		}

		// Extrair CWEs
		cwes := extractCWEs(vuln)
		if len(cwes) == 0 {
			continue // Pular CVEs sem CWEs
		}

		// Mapear para vetores de ataque
		vectors := mapToAttackVectors(cwes, cweMap)
		if len(vectors) == 0 {
			continue // Pular CVEs sem vetores mapeados
		}

		totalWithVectors++

		// Criar registro de treinamento
		trainingData = append(trainingData, TrainingRecord{
			CVEID:         vuln.CVE.ID,
			Description:   description,
			CWEs:          cwes,
			AttackVectors: vectors,
			PublishedDate: vuln.CVE.Published,
		})
	}

	fmt.Printf("  Processed %d/%d CVEs (%d with attack vectors)\n\n", totalProcessed, len(feed.Vulnerabilities), totalWithVectors)

	// Salvar dados de treinamento
	fmt.Println("=================================================================")
	fmt.Printf("Collection complete!\n")
	fmt.Printf("  Total CVEs processed: %d\n", totalProcessed)
	fmt.Printf("  CVEs with attack vectors: %d\n", totalWithVectors)
	fmt.Printf("  Saving to: %s\n\n", outputFile)

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Serializar com indentação para legibilidade
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(trainingData); err != nil {
		fmt.Printf("Error writing training data: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Training data saved successfully!\n")

	// Mostrar distribuição de vetores de ataque
	vectorCounts := make(map[string]int)
	for _, record := range trainingData {
		for _, vector := range record.AttackVectors {
			vectorCounts[vector]++
		}
	}

	fmt.Println("=================================================================")
	fmt.Println("Attack Vector Distribution:")
	fmt.Println("=================================================================")
	for _, mapping := range attackVectorMappings {
		if count, ok := vectorCounts[mapping.Name]; ok {
			fmt.Printf("  %-30s: %5d CVEs\n", mapping.Description, count)
		}
	}

	fmt.Println("\nPhase 1 complete! Ready for Phase 2 (Naive Bayes training)")
}
