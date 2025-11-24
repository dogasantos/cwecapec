package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// ESTRUTURAS DE DADOS - DADOS DE TREINAMENTO
// ============================================================================

// CVEEntry representa um registro individual de CVE do dataset de treinamento,
// contendo todas as informações necessárias para reclassificação
type CVEEntry struct {
	CVEID         string   `json:"cve_id"`         // ID do CVE (ex: "CVE-2024-12345")
	Description   string   `json:"description"`    // Descrição textual da vulnerabilidade
	CWEs          []string `json:"cwes"`           // Lista de IDs de CWE associados (ex: ["89", "20"])
	AttackVectors []string `json:"attack_vectors"` // Vetores de ataque classificados (ex: ["sql_injection"])
	PublishedDate string   `json:"published_date"` // Data de publicação do CVE
}

// ============================================================================
// ESTRUTURAS DE DADOS - HIERARQUIA CWE
// ============================================================================

// CWEInfo contém informações detalhadas sobre um CWE específico,
// incluindo sua posição na hierarquia e vetores de ataque associados
type CWEInfo struct {
	ID            string   `json:"id"`             // ID do CWE (ex: "89")
	Name          string   `json:"name"`           // Nome do CWE (ex: "SQL Injection")
	Abstraction   string   `json:"abstraction"`    // Nível de abstração (Base, Variant, Class, etc.)
	Parents       []string `json:"parents"`        // IDs dos CWEs pais na hierarquia
	Children      []string `json:"children"`       // IDs dos CWEs filhos na hierarquia
	AttackVectors []string `json:"attack_vectors"` // Vetores de ataque mapeados para este CWE
}

// CWEHierarchy representa a estrutura completa da hierarquia CWE
// com mapeamentos bidirecionais entre CWEs e vetores de ataque
type CWEHierarchy struct {
	CWEs                map[string]*CWEInfo `json:"cwes"`                   // Mapa de CWE ID para informações do CWE
	AttackVectorMapping map[string][]string `json:"attack_vector_mapping"`  // Mapa de CWE ID para vetores de ataque
	CWEToVectorMapping  map[string][]string // Mapeamento reverso (construído em tempo de execução)
}

// ============================================================================
// ESTRUTURAS DE DADOS - MODELO NAIVE BAYES
// ============================================================================

// AttackVectorModel representa o modelo Naive Bayes treinado para
// classificação de vetores de ataque baseada em texto
type AttackVectorModel struct {
	AttackVectors   []string                      `json:"attack_vectors"`    // Lista de todos os vetores de ataque
	VectorPriors    map[string]float64            `json:"vector_priors"`     // Probabilidades a priori P(vetor)
	WordGivenVector map[string]map[string]float64 `json:"word_given_vector"` // Probabilidades P(palavra|vetor)
	WordCounts      map[string]map[string]int     `json:"word_counts"`       // Contagens brutas de palavras
	TotalWords      map[string]int                `json:"total_words"`       // Total de palavras por vetor
	Vocabulary      []string                      `json:"vocabulary"`        // Vocabulário completo
	TotalDocuments  int                           `json:"total_documents"`   // Total de documentos de treinamento
	VectorDocCounts map[string]int                `json:"vector_doc_counts"` // Contagem de documentos por vetor
}

// ============================================================================
// ESTRUTURAS DE DADOS - TAXONOMIA DE PADRÕES
// ============================================================================

// Pattern representa um padrão de palavras-chave que indica um vetor de ataque específico
type Pattern struct {
	Keywords    []string `json:"keywords"`    // Lista de palavras-chave do padrão
	Specificity float64  `json:"specificity"` // Especificidade do padrão (0-1)
	Boost       float64  `json:"boost"`       // Multiplicador de pontuação
	Support     int      `json:"support"`     // Número de CVEs que contêm este padrão
}

// PatternTaxonomy contém todos os padrões organizados por vetor de ataque
type PatternTaxonomy struct {
	Patterns map[string][]Pattern `json:"patterns"` // Mapa de vetor de ataque para lista de padrões
}

// ============================================================================
// ESTRUTURAS DE DADOS - RESULTADOS DE CLASSIFICAÇÃO
// ============================================================================

// ClassificationResult representa o resultado da classificação de um vetor de ataque
// com sua probabilidade e fonte de classificação
type ClassificationResult struct {
	Vector      string  `json:"vector"`      // Nome do vetor de ataque
	Probability float64 `json:"probability"` // Probabilidade ou pontuação (0-1)
	Source      string  `json:"source"`      // Fonte da classificação ("naive_bayes", "pattern", etc.)
}

// ScoredCWE representa um CWE com sua pontuação de relevância
// usado para ranquear CWEs por importância para um CVE específico
type ScoredCWE struct {
	ID    string  // ID do CWE
	Score float64 // Pontuação de relevância
}

// ============================================================================
// VARIÁVEIS GLOBAIS
// ============================================================================

// Recursos carregados uma vez e compartilhados por todos os workers
var (
	cweHierarchy    *CWEHierarchy       // Hierarquia CWE carregada
	nbModel         *AttackVectorModel  // Modelo Naive Bayes carregado
	patternTaxonomy *PatternTaxonomy    // Taxonomia de padrões carregada
	resourcesPath   = "resources"       // Diretório de recursos
	debugMode       = true              // Habilitar saída de debug para os primeiros 10 CVEs
	debugCount      = 0                 // Contador de CVEs debugados
	debugMutex      sync.Mutex          // Mutex para acesso thread-safe ao contador de debug
}

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

/*
 * Função: main
 * Descrição: Ponto de entrada do programa que orquestra a reclassificação em lote
 *            de todos os CVEs do dataset de treinamento usando o classificador híbrido
 * Objetivo: Melhorar a qualidade dos dados de treinamento aplicando a lógica de
 *           classificação mais recente e sofisticada (Phase 4) sobre todos os CVEs
 *           existentes, corrigindo classificações desatualizadas ou incorretas
 * Como faz: 1. Carrega todos os recursos necessários (hierarquia CWE, modelo NB, padrões)
 *           2. Carrega o dataset de treinamento completo
 *           3. Reclassifica todos os CVEs em paralelo usando 8 workers
 *           4. Salva os resultados atualizados sobrescrevendo o arquivo original
 *           5. Gera estatísticas mostrando quantos CVEs foram alterados
 * Input: Arquivos em resources/:
 *        - cwe_hierarchy.json (hierarquia CWE)
 *        - naive_bayes_model.json (modelo treinado)
 *        - pattern_taxonomy.json (padrões de ataque)
 *        - training_data.json (dados de treinamento originais)
 * Output: Arquivo resources/training_data.json atualizado com novas classificações
 *         e relatório estatístico no console
 * Por que faz: À medida que os modelos e algoritmos de classificação melhoram,
 *              os rótulos originais dos dados de treinamento podem ficar desatualizados.
 *              Esta ferramenta cria um ciclo de feedback que melhora continuamente
 *              a qualidade dos dados, resultando em modelos mais precisos no futuro.
 */
func main() {
	fmt.Println("=================================================================")
	fmt.Println("Batch Re-Classification Tool")
	fmt.Println("Re-classifies training data using Phase 4 hybrid classifier")
	fmt.Println("=================================================================\n")

	// Carregar a hierarquia CWE
	fmt.Print("Loading CWE hierarchy... ")
	if err := loadCWEHierarchy(); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Carregar o modelo Naive Bayes
	fmt.Print("Loading Naive Bayes model... ")
	if err := loadNaiveBayesModel(); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Carregar a taxonomia de padrões
	fmt.Print("Loading pattern taxonomy... ")
	if err := loadPatternTaxonomy(); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Carregar os dados de treinamento
	fmt.Print("Loading training data... ")
	trainingData, err := loadTrainingData()
	if err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ (%d CVEs loaded)\n\n", len(trainingData))

	// Reclassificar todos os CVEs
	fmt.Println("Starting re-classification...")
	startTime := time.Now()

	reclassified := reclassifyBatch(trainingData)

	elapsed := time.Since(startTime)
	fmt.Printf("\nRe-classification complete in %v\n", elapsed)
	fmt.Printf("Average: %.2f CVEs/second\n\n", float64(len(trainingData))/elapsed.Seconds())

	// Salvar os resultados
	outputPath := resourcesPath + "/training_data.json"
	fmt.Printf("Saving results to %s... ", outputPath)
	if err := saveTrainingData(reclassified, outputPath); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Gerar estatísticas
	fmt.Println("\n=================================================================")
	fmt.Println("Re-classification Statistics")
	fmt.Println("=================================================================")
	generateStats(trainingData, reclassified)
}

// ============================================================================
// FUNÇÕES DE CARREGAMENTO DE RECURSOS
// ============================================================================

/*
 * Função: loadCWEHierarchy
 * Descrição: Carrega a hierarquia CWE do arquivo JSON e constrói o mapeamento reverso
 * Objetivo: Ler a estrutura hierárquica do CWE e criar índices para consulta rápida
 *           de vetores de ataque associados a cada CWE
 * Como faz: 1. Abre e lê o arquivo cwe_hierarchy.json
 *           2. Desserializa para a estrutura CWEHierarchy
 *           3. Constrói o mapeamento reverso (CWE ID -> Vetores de Ataque)
 *           4. Armazena na variável global cweHierarchy
 * Input: Arquivo resources/cwe_hierarchy.json
 * Output: error - nil se bem-sucedido, erro caso contrário
 * Por que faz: A hierarquia CWE é fundamental para a primeira camada de classificação,
 *              permitindo mapear CWEs conhecidos para vetores de ataque candidatos.
 */
func loadCWEHierarchy() error {
	file, err := os.Open(resourcesPath + "/cwe_hierarchy.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	cweHierarchy = &CWEHierarchy{}
	if err := json.Unmarshal(data, cweHierarchy); err != nil {
		return err
	}

	// Construir mapeamento reverso (CWE ID -> Vetores de Ataque)
	cweHierarchy.CWEToVectorMapping = make(map[string][]string)
	for cweID, vectors := range cweHierarchy.AttackVectorMapping {
		cweHierarchy.CWEToVectorMapping[cweID] = vectors
	}

	return nil
}

/*
 * Função: loadNaiveBayesModel
 * Descrição: Carrega o modelo Naive Bayes treinado do arquivo JSON
 * Objetivo: Ler o modelo probabilístico treinado para classificação de texto
 * Como faz: 1. Abre e lê o arquivo naive_bayes_model.json
 *           2. Desserializa para a estrutura AttackVectorModel
 *           3. Armazena na variável global nbModel
 * Input: Arquivo resources/naive_bayes_model.json
 * Output: error - nil se bem-sucedido, erro caso contrário
 * Por que faz: O modelo Naive Bayes é a segunda camada de classificação,
 *              fornecendo classificação probabilística baseada no texto da descrição.
 */
func loadNaiveBayesModel() error {
	file, err := os.Open(resourcesPath + "/naive_bayes_model.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	nbModel = &AttackVectorModel{}
	return json.Unmarshal(data, nbModel)
}

/*
 * Função: loadPatternTaxonomy
 * Descrição: Carrega a taxonomia de padrões de palavras-chave do arquivo JSON
 * Objetivo: Ler os padrões de alta confiança para detecção de vetores de ataque
 * Como faz: 1. Abre e lê o arquivo pattern_taxonomy.json
 *           2. Desserializa para a estrutura PatternTaxonomy
 *           3. Armazena na variável global patternTaxonomy
 * Input: Arquivo resources/pattern_taxonomy.json
 * Output: error - nil se bem-sucedido, erro caso contrário
 * Por que faz: A correspondência de padrões é a terceira camada de classificação,
 *              fornecendo detecção rápida e precisa baseada em palavras-chave específicas.
 */
func loadPatternTaxonomy() error {
	file, err := os.Open(resourcesPath + "/pattern_taxonomy.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	patternTaxonomy = &PatternTaxonomy{}
	return json.Unmarshal(data, patternTaxonomy)
}

/*
 * Função: loadTrainingData
 * Descrição: Carrega o dataset de treinamento completo do arquivo JSON
 * Objetivo: Ler todos os registros de CVE que serão reclassificados
 * Como faz: 1. Abre e lê o arquivo training_data.json
 *           2. Desserializa para um slice de CVEEntry
 *           3. Retorna o slice completo
 * Input: Arquivo resources/training_data.json
 * Output: ([]CVEEntry, error) - Slice de CVEs ou erro
 * Por que faz: Os dados de treinamento são a entrada principal para reclassificação.
 */
func loadTrainingData() ([]CVEEntry, error) {
	file, err := os.Open(resourcesPath + "/training_data.json")
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

/*
 * Função: saveTrainingData
 * Descrição: Salva o dataset de treinamento reclassificado de volta ao arquivo JSON
 * Objetivo: Persistir as novas classificações sobrescrevendo o arquivo original
 * Como faz: 1. Cria (sobrescreve) o arquivo de saída
 *           2. Configura o encoder JSON com indentação
 *           3. Serializa o slice de CVEEntry para JSON
 *           4. Escreve no arquivo
 * Input: entries ([]CVEEntry) - Slice de CVEs reclassificados
 *        path (string) - Caminho do arquivo de saída
 * Output: error - nil se bem-sucedido, erro caso contrário
 * Por que faz: As novas classificações precisam ser persistidas para serem usadas
 *              em futuros treinamentos de modelo.
 */
func saveTrainingData(entries []CVEEntry, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}

// ============================================================================
// FUNÇÃO DE RECLASSIFICAÇÃO EM LOTE
// ============================================================================

/*
 * Função: reclassifyBatch
 * Descrição: Reclassifica todos os CVEs em paralelo usando um pool de workers
 * Objetivo: Processar eficientemente milhares de CVEs usando múltiplas goroutines
 *           para maximizar o throughput e minimizar o tempo total de processamento
 * Como faz: 1. Cria um slice de resultados do mesmo tamanho da entrada
 *           2. Configura rastreamento de progresso com mutex para thread-safety
 *           3. Cria um canal de jobs e um pool de 8 workers
 *           4. Cada worker processa CVEs do canal:
 *              a. Ranqueia os CWEs por relevância (top 2)
 *              b. Classifica usando o classificador híbrido
 *              c. Atualiza os vetores de ataque do CVE
 *              d. Armazena o resultado no slice
 *              e. Atualiza o progresso (exibe a cada 1000 CVEs)
 *           5. Aguarda todos os workers terminarem
 *           6. Retorna o slice de CVEs reclassificados
 * Input: entries ([]CVEEntry) - Slice de CVEs originais
 * Output: []CVEEntry - Slice de CVEs com vetores de ataque atualizados
 * Por que faz: Processar milhares de CVEs sequencialmente seria muito lento.
 *              O processamento paralelo com 8 workers aproveita múltiplos núcleos
 *              da CPU e reduz significativamente o tempo total de execução.
 */
func reclassifyBatch(entries []CVEEntry) []CVEEntry {
	results := make([]CVEEntry, len(entries))

	// Rastreamento de progresso
	total := len(entries)
	processed := 0
	var mu sync.Mutex

	// Processar em paralelo usando pool de workers
	numWorkers := 8
	jobs := make(chan int, total)
	var wg sync.WaitGroup

	// Iniciar workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				entry := entries[i]

				// --- LÓGICA MODIFICADA INÍCIO ---

				// Passo 1: Ranquear CWEs por relevância e selecionar os top 2
				rankedCWEs := rankCWEsByRelevance(entry.CWEs, entry.Description, cweHierarchy, 2)

				// Passo 2: Classificar usando abordagem híbrida, mas apenas com os top 2 CWEs
				vectors := classifyHybrid(entry.Description, rankedCWEs, entry.CVEID)

				// --- LÓGICA MODIFICADA FIM ---

				// Atualizar vetores de ataque
				entry.AttackVectors = vectors
				results[i] = entry

				// Atualizar progresso
				mu.Lock()
				processed++
				if processed%1000 == 0 || processed == total {
					fmt.Printf("\rProgress: %d/%d (%.1f%%)", processed, total, float64(processed)*100/float64(total))
				}
				mu.Unlock()
			}
		}()
	}

	// Enviar jobs
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)

	// Aguardar conclusão
	wg.Wait()

	return results
}

// ============================================================================
// LÓGICA DE RANQUEAMENTO DE CWE (Copiada do phase4-relationship.go)
// ============================================================================

/*
 * Função: rankCWEsByRelevance
 * Descrição: Ranqueia uma lista de CWEs por relevância para um CVE específico
 *            e retorna os top N mais relevantes
 * Objetivo: Filtrar CWEs genéricos ou menos relevantes, focando apenas nos
 *           CWEs mais importantes para melhorar a precisão da classificação
 * Como faz: 1. Para cada CWE na lista:
 *              a. Calcula uma pontuação de relevância baseada em:
 *                 - Correspondência de palavras-chave na descrição
 *                 - Prioridade do CWE (CWEs críticos recebem boost)
 *                 - Padrões específicos na descrição
 *                 - Penalidades para CWEs genéricos
 *              b. Armazena o CWE com sua pontuação
 *           2. Ordena os CWEs por pontuação (ordem decrescente)
 *           3. Retorna os top N CWEs
 * Input: cweIDs ([]string) - Lista de IDs de CWE
 *        description (string) - Descrição do CVE
 *        hierarchy (*CWEHierarchy) - Hierarquia CWE para consulta
 *        topN (int) - Número de top CWEs a retornar
 * Output: []string - Slice com os IDs dos top N CWEs mais relevantes
 * Por que faz: Muitos CVEs têm múltiplos CWEs, alguns genéricos (como CWE-20).
 *              Ranquear por relevância garante que apenas os CWEs mais específicos
 *              e importantes sejam usados na classificação, melhorando a precisão.
 */
func rankCWEsByRelevance(cweIDs []string, description string, hierarchy *CWEHierarchy, topN int) []string {
	if len(cweIDs) == 0 {
		return []string{}
	}

	// Pontuar cada CWE
	scoredCWEs := []ScoredCWE{}
	descLower := strings.ToLower(description)

	for _, cweID := range cweIDs {
		score := scoreCWERelevance(cweID, descLower, hierarchy)
		scoredCWEs = append(scoredCWEs, ScoredCWE{
			ID:    cweID,
			Score: score,
		})
	}

	// Ordenar por pontuação (ordem decrescente)
	sort.Slice(scoredCWEs, func(i, j int) bool {
		return scoredCWEs[i].Score > scoredCWEs[j].Score
	})

	// Pegar os top N
	resultCount := topN
	if len(scoredCWEs) < topN {
		resultCount = len(scoredCWEs)
	}

	result := make([]string, resultCount)
	for i := 0; i < resultCount; i++ {
		result[i] = scoredCWEs[i].ID
	}

	return result
}

/*
 * Função: scoreCWERelevance
 * Descrição: Calcula uma pontuação de relevância para um CWE específico baseada
 *            na descrição do CVE e em heurísticas de priorização
 * Objetivo: Determinar quão relevante um CWE é para um CVE específico usando
 *           múltiplos critérios de pontuação
 * Como faz: 1. Correspondência de palavras-chave do nome do CWE na descrição (+10 por match)
 *           2. Boost de prioridade para CWEs críticos conhecidos (+25 a +50)
 *           3. Boost baseado em padrões específicos na descrição (+50 a +100):
 *              - Desserialização: CWE-502, CWE-917
 *              - Injeção de código: CWE-94
 *              - SQL Injection: CWE-89
 *              - XSS: CWE-79
 *              - Path Traversal: CWE-22
 *              - SSRF: CWE-918
 *              - XXE: CWE-611
 *              - Buffer Overflow: CWE-119, CWE-787
 *              - Auth/Authz Bypass: CWE-306, CWE-862, CWE-269
 *           4. Penalidade para CWEs genéricos (-15 a -20)
 *           5. Boost para CWEs com mapeamentos de vetor de ataque (+5 por vetor)
 *           6. Garante pontuação mínima de 0
 * Input: cweID (string) - ID do CWE a pontuar
 *        descLower (string) - Descrição do CVE em minúsculas
 *        hierarchy (*CWEHierarchy) - Hierarquia CWE para consulta
 * Output: float64 - Pontuação de relevância (0+, maior = mais relevante)
 * Por que faz: Nem todos os CWEs associados a um CVE são igualmente importantes.
 *              Esta função usa heurísticas sofisticadas para identificar os CWEs
 *              mais relevantes, melhorando a precisão da classificação de vetores.
 */
func scoreCWERelevance(cweID string, descLower string, hierarchy *CWEHierarchy) float64 {
	cwe, exists := hierarchy.CWEs[cweID]
	if !exists {
		return 0.0
	}

	score := 0.0
	cweName := strings.ToLower(cwe.Name)

	// 1. Correspondência de palavras-chave base
	keywords := extractCWEKeywords(cweName)
	for _, keyword := range keywords {
		if len(keyword) < 3 {
			continue
		}
		if strings.Contains(descLower, keyword) {
			score += 10.0
		}
	}

	// 2. Boost de prioridade para CWEs críticos
	priorityCWEs := map[string]float64{
		"502": 50.0, "78": 45.0, "79": 40.0, "89": 45.0, "94": 45.0,
		"77": 40.0, "22": 35.0, "434": 35.0, "611": 35.0, "918": 40.0,
		"917": 40.0, "119": 30.0, "787": 30.0, "416": 30.0, "352": 25.0,
		"306": 25.0, "862": 25.0,
	}
	if boost, exists := priorityCWEs[cweID]; exists {
		score += boost
	}

	// 3. Boost baseado em padrões
	if containsAnyPattern(descLower, []string{"deserializ", "jndi", "ldap", "lookup", "unmarsh", "pickle"}) {
		if cweID == "502" {
			score += 100.0
		}
		if cweID == "917" {
			score += 50.0
		}
	}

	if containsAnyPattern(descLower, []string{"inject", "execut", "eval", "code execution"}) {
		if containsAnyPattern(descLower, []string{"code", "arbitrary"}) && cweID == "94" {
			score += 80.0
		}
	}

	if containsAnyPattern(descLower, []string{"sql", "database", "query"}) && cweID == "89" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"xss", "cross-site scripting", "script injection"}) && cweID == "79" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"path traversal", "directory traversal", "../", "..\\", "path manipulation"}) && cweID == "22" {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"ssrf", "server-side request", "internal request", "url fetch"}) && cweID == "918" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"xxe", "xml external entity", "xml injection"}) && cweID == "611" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"buffer overflow", "buffer overrun", "heap overflow", "stack overflow"}) && (cweID == "119" || cweID == "787") {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"authentication bypass", "auth bypass", "without authentication"}) && cweID == "306" {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"authorization bypass", "privilege escalation", "unauthorized access"}) && (cweID == "862" || cweID == "269") {
		score += 80.0
	}

	// 4. Penalidade para CWEs genéricos
	genericCWEs := map[string]float64{
		"20": -20.0, "400": -15.0, "703": -20.0, "707": -20.0,
	}
	if penalty, exists := genericCWEs[cweID]; exists {
		score += penalty
	}

	// 5. Boost para CWEs com mapeamentos de vetor de ataque
	if cwe, exists := hierarchy.CWEs[cweID]; exists && len(cwe.AttackVectors) > 0 {
		score += float64(len(cwe.AttackVectors)) * 5.0
	}

	if score < 0 {
		score = 0
	}

	return score
}

/*
 * Função: extractCWEKeywords
 * Descrição: Extrai palavras-chave significativas do nome de um CWE
 * Objetivo: Obter termos relevantes do nome do CWE para correspondência com a descrição
 * Como faz: 1. Remove stopwords comuns (improper, insufficient, the, of, etc.)
 *           2. Divide o texto em palavras usando regex
 *           3. Filtra palavras com menos de 3 caracteres
 *           4. Retorna lista de palavras-chave
 * Input: text (string) - Nome do CWE
 * Output: []string - Lista de palavras-chave extraídas
 * Por que faz: Nomes de CWE contêm muitas stopwords genéricas. Extrair apenas
 *              palavras-chave significativas melhora a correspondência com descrições.
 */
func extractCWEKeywords(text string) []string {
	stopWords := map[string]bool{
		"improper": true, "insufficient": true, "incorrect": true,
		"missing": true, "lack": true, "inadequate": true,
		"the": true, "of": true, "in": true, "to": true, "for": true,
		"and": true, "or": true, "a": true, "an": true,
	}

	re := regexp.MustCompile(`[^a-z0-9]+`)
	words := re.Split(text, -1)

	keywords := []string{}
	for _, word := range words {
		word = strings.ToLower(word)
		if len(word) >= 3 && !stopWords[word] {
			keywords = append(keywords, word)
		}
	}

	return keywords
}

/*
 * Função: containsAnyPattern
 * Descrição: Verifica se um texto contém qualquer um dos padrões fornecidos
 * Objetivo: Detectar rapidamente a presença de termos específicos no texto
 * Como faz: Itera pela lista de padrões e verifica se algum está contido no texto
 * Input: text (string) - Texto a verificar
 *        patterns ([]string) - Lista de padrões a procurar
 * Output: bool - true se qualquer padrão for encontrado, false caso contrário
 * Por que faz: Função auxiliar usada para detecção de padrões na pontuação de CWEs.
 */
func containsAnyPattern(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

// ============================================================================
// LÓGICA DE CLASSIFICAÇÃO HÍBRIDA (Modificada para usar apenas os CWEs fornecidos)
// ============================================================================

/*
 * Função: classifyHybrid
 * Descrição: Classifica um CVE usando uma abordagem híbrida de três camadas
 *            (hierarquia CWE + Naive Bayes + padrões)
 * Objetivo: Combinar múltiplos métodos de classificação para obter resultados
 *           mais precisos do que qualquer método individual
 * Como faz: 1. Camada 1 - Hierarquia CWE: Mapeia CWEs para vetores candidatos
 *           2. Se nenhum candidato, retorna ["unknown"]
 *           3. Camada 2 - Naive Bayes: Classifica apenas os candidatos
 *           4. Camada 3 - Padrões: Detecta padrões apenas nos candidatos
 *           5. Combina resultados com pontuações ponderadas:
 *              - Base: +3.0 para todos os candidatos da hierarquia
 *              - Naive Bayes: +probabilidade * 2.0
 *              - Padrões: +probabilidade * 1.5
 *           6. Ordena por pontuação e retorna os top 3 vetores únicos
 *           7. Exibe debug para os primeiros 10 CVEs (se debugMode = true)
 * Input: description (string) - Descrição do CVE
 *        cweIDs ([]string) - Lista de CWE IDs (já ranqueados, top 2)
 *        cveID (string) - ID do CVE (para debug)
 * Output: []string - Lista dos top 3 vetores de ataque classificados
 * Por que faz: A abordagem híbrida combina os pontos fortes de cada método:
 *              - Hierarquia: garante que apenas vetores relevantes sejam considerados
 *              - Naive Bayes: fornece classificação probabilística baseada em texto
 *              - Padrões: detecta indicadores específicos de alta confiança
 *              O resultado é mais preciso e robusto do que qualquer método isolado.
 */
func classifyHybrid(description string, cweIDs []string, cveID string) []string {
	debugMutex.Lock()
	showDebug := debugMode && debugCount < 10
	if showDebug {
		debugCount++
	}
	debugMutex.Unlock()

	if showDebug {
		fmt.Printf("\n=== DEBUG: %s ===\n", cveID)
		fmt.Printf("Description: %s\n", description)
		fmt.Printf("CWEs: %v\n", cweIDs)
	}

	// Camada 1: Hierarquia CWE - Obter vetores candidatos (filtro)
	candidates := classifyByCWEHierarchy(cweIDs)
	if showDebug {
		fmt.Printf("\nLayer 1 - CWE Hierarchy Candidates: ")
		for v := range candidates {
			fmt.Printf("%s ", v)
		}
		fmt.Println()
	}

	// Se nenhum candidato da hierarquia CWE, retornar unknown
	if len(candidates) == 0 {
		return []string{"unknown"}
	}

	// Camada 2: Classificação Naive Bayes (apenas nos candidatos)
	nbResults := classifyByNaiveBayes(description, candidates)
	if showDebug {
		fmt.Printf("\nLayer 2 - Naive Bayes (top 5):\n")
		for i := 0; i < 5 && i < len(nbResults); i++ {
			fmt.Printf("  %s: %.4f\n", nbResults[i].Vector, nbResults[i].Probability)
		}
	}

	// Camada 3: Correspondência de padrões (apenas nos candidatos)
	patternResults := classifyByPatterns(description, candidates)
	if showDebug {
		fmt.Printf("\nLayer 3 - Pattern Matching (top 5):\n")
		for i := 0; i < 5 && i < len(patternResults); i++ {
			fmt.Printf("  %s: %.4f\n", patternResults[i].Vector, patternResults[i].Probability)
		}
	}

	// Combinar resultados
	vectorScores := make(map[string]float64)

	// Adicionar pontuação base para todos os candidatos da hierarquia
	for v := range candidates {
		vectorScores[v] = 3.0
	}

	// Adicionar resultados do Naive Bayes
	for _, result := range nbResults {
		vectorScores[result.Vector] += result.Probability * 2.0
	}

	// Adicionar resultados de padrões
	for _, result := range patternResults {
		vectorScores[result.Vector] += result.Probability * 1.5
	}

	// Obter os top vetores
	type scoredVector struct {
		vector string
		score  float64
	}

	var scored []scoredVector
	for v, s := range vectorScores {
		scored = append(scored, scoredVector{v, s})
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			// Desempate: ordenar alfabeticamente para consistência
			return scored[i].vector < scored[j].vector
		}
		return scored[i].score > scored[j].score
	})

	if showDebug {
		fmt.Printf("\nCombined Scores (top 10):\n")
		for i := 0; i < 10 && i < len(scored); i++ {
			fmt.Printf("  %s: %.4f\n", scored[i].vector, scored[i].score)
		}
	}

	// Retornar os top 3 vetores únicos
	var result []string
	seen := make(map[string]bool)
	for _, sv := range scored {
		if !seen[sv.vector] && len(result) < 3 {
			result = append(result, sv.vector)
			seen[sv.vector] = true
		}
	}

	// Se nenhum vetor encontrado, retornar "unknown"
	if len(result) == 0 {
		result = []string{"unknown"}
	}

	return result
}

/*
 * Função: classifyByCWEHierarchy
 * Descrição: Mapeia uma lista de CWE IDs para vetores de ataque candidatos
 *            usando a hierarquia CWE
 * Objetivo: Primeira camada de classificação que filtra vetores de ataque
 *           relevantes baseados nos CWEs conhecidos
 * Como faz: 1. Para cada CWE ID:
 *              a. Busca mapeamento direto (CWE -> Vetores)
 *              b. Busca mapeamento de pais (CWE -> Pais -> Vetores)
 *           2. Adiciona todos os vetores encontrados ao conjunto de candidatos
 *           3. Retorna o mapa de candidatos
 * Input: cweIDs ([]string) - Lista de IDs de CWE
 * Output: map[string]bool - Mapa de vetores de ataque candidatos (chave = vetor, valor = true)
 * Por que faz: A hierarquia CWE fornece um filtro inicial forte, garantindo que
 *              apenas vetores de ataque relevantes sejam considerados nas camadas
 *              subsequentes, melhorando a eficiência e precisão.
 */
func classifyByCWEHierarchy(cweIDs []string) map[string]bool {
	candidates := make(map[string]bool)

	for _, cweID := range cweIDs {
		// Mapeamento direto
		if vectors, exists := cweHierarchy.CWEToVectorMapping[cweID]; exists {
			for _, v := range vectors {
				candidates[v] = true
			}
		}

		// Mapeamento de pais
		if cweInfo, exists := cweHierarchy.CWEs[cweID]; exists {
			for _, parentID := range cweInfo.Parents {
				if vectors, exists := cweHierarchy.CWEToVectorMapping[parentID]; exists {
					for _, v := range vectors {
						candidates[v] = true
					}
				}
			}
		}
	}

	return candidates
}

/*
 * Função: classifyByNaiveBayes
 * Descrição: Classifica a descrição do CVE usando o modelo Naive Bayes treinado,
 *            considerando apenas os vetores candidatos
 * Objetivo: Segunda camada de classificação que fornece probabilidades baseadas
 *           na análise estatística do texto da descrição
 * Como faz: 1. Tokeniza a descrição em palavras
 *           2. Para cada vetor candidato:
 *              a. Calcula log-probabilidade: log(P(vetor)) + Σlog(P(palavra|vetor))
 *           3. Normaliza as pontuações para probabilidades (0-1):
 *              a. Encontra a pontuação máxima
 *              b. Aplica exp(score - max_score) para estabilidade numérica
 *              c. Normaliza dividindo pela soma total
 *           4. Ordena por probabilidade (ordem decrescente)
 *           5. Retorna os top 3 vetores com suas probabilidades
 * Input: description (string) - Descrição do CVE
 *        candidates (map[string]bool) - Mapa de vetores candidatos
 * Output: []ClassificationResult - Lista dos top 3 resultados com probabilidades
 * Por que faz: O Naive Bayes fornece classificação probabilística baseada em
 *              padrões aprendidos de milhares de CVEs, capturando relações
 *              estatísticas entre palavras e vetores de ataque.
 */
func classifyByNaiveBayes(description string, candidates map[string]bool) []ClassificationResult {
	words := tokenize(description)
	scores := make(map[string]float64)

	for _, vector := range nbModel.AttackVectors {
		// Pular se não for um candidato
		if !candidates[vector] {
			continue
		}

		logProb := math.Log(nbModel.VectorPriors[vector])

		for _, word := range words {
			if prob, exists := nbModel.WordGivenVector[vector][word]; exists {
				logProb += math.Log(prob)
			}
		}

		scores[vector] = logProb
	}

	// Normalizar para probabilidades
	maxScore := -math.MaxFloat64
	for _, score := range scores {
		if score > maxScore {
			maxScore = score
		}
	}

	total := 0.0
	for vector := range scores {
		scores[vector] = math.Exp(scores[vector] - maxScore)
		total += scores[vector]
	}

	for vector := range scores {
		scores[vector] /= total
	}

	// Retornar os top 3
	type scoredVector struct {
		vector string
		prob   float64
	}

	var sorted []scoredVector
	for v, p := range scores {
		sorted = append(sorted, scoredVector{v, p})
	}

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].prob == sorted[j].prob {
			// Desempate: ordenar alfabeticamente para consistência
			return sorted[i].vector < sorted[j].vector
		}
		return sorted[i].prob > sorted[j].prob
	})

	var results []ClassificationResult
	for i := 0; i < 3 && i < len(sorted); i++ {
		results = append(results, ClassificationResult{
			Vector:      sorted[i].vector,
			Probability: sorted[i].prob,
			Source:      "naive_bayes",
		})
	}

	return results
}

/*
 * Função: classifyByPatterns
 * Descrição: Classifica a descrição do CVE usando correspondência de padrões
 *            de palavras-chave, considerando apenas os vetores candidatos
 * Objetivo: Terceira camada de classificação que detecta indicadores específicos
 *           de alta confiança através de palavras-chave características
 * Como faz: 1. Converte a descrição para minúsculas
 *           2. Para cada vetor candidato:
 *              a. Para cada padrão do vetor:
 *                 - Verifica se TODAS as palavras-chave estão presentes
 *                 - Se sim, adiciona (boost/100) * specificity à pontuação
 *              b. Limita o boost máximo a 5.0 para evitar dominar outras camadas
 *           3. Ordena por pontuação (ordem decrescente)
 *           4. Retorna os top 3 vetores com suas pontuações
 * Input: description (string) - Descrição do CVE
 *        candidates (map[string]bool) - Mapa de vetores candidatos
 * Output: []ClassificationResult - Lista dos top 3 resultados com pontuações
 * Por que faz: Padrões de palavras-chave fornecem detecção rápida e precisa de
 *              vetores de ataque quando termos técnicos específicos estão presentes,
 *              complementando a análise probabilística do Naive Bayes.
 */
func classifyByPatterns(description string, candidates map[string]bool) []ClassificationResult {
	descLower := strings.ToLower(description)
	vectorScores := make(map[string]float64)

	for vector, patterns := range patternTaxonomy.Patterns {
		// Pular se não for um candidato
		if !candidates[vector] {
			continue
		}

		totalBoost := 0.0

		for _, pattern := range patterns {
			// Verificar se todas as palavras-chave do padrão estão presentes
			allMatch := true
			for _, keyword := range pattern.Keywords {
				if !strings.Contains(descLower, keyword) {
					allMatch = false
					break
				}
			}

			if allMatch {
				// Normalizar boost (dividir por 100 já que todos os boosts são 100.0)
				// e ponderar pela especificidade
				totalBoost += (pattern.Boost / 100.0) * pattern.Specificity
			}
		}

		// Limitar o boost máximo por vetor para evitar dominar outras camadas
		if totalBoost > 5.0 {
			totalBoost = 5.0
		}

		if totalBoost > 0 {
			vectorScores[vector] = totalBoost
		}
	}

	// Ordenar por pontuação
	type scoredVector struct {
		vector string
		score  float64
	}

	var sorted []scoredVector
	for v, s := range vectorScores {
		sorted = append(sorted, scoredVector{v, s})
	}

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].score == sorted[j].score {
			// Desempate: ordenar alfabeticamente para consistência
			return sorted[i].vector < sorted[j].vector
		}
		return sorted[i].score > sorted[j].score
	})

	var results []ClassificationResult
	for i := 0; i < 3 && i < len(sorted); i++ {
		results = append(results, ClassificationResult{
			Vector:      sorted[i].vector,
			Probability: sorted[i].score,
			Source:      "pattern",
		})
	}

	return results
}

/*
 * Função: tokenize
 * Descrição: Tokeniza um texto em palavras individuais, removendo stopwords
 *            e caracteres especiais
 * Objetivo: Preparar o texto para análise pelo modelo Naive Bayes
 * Como faz: 1. Converte para minúsculas
 *           2. Remove caracteres especiais (mantém apenas alfanuméricos e espaços)
 *           3. Divide em palavras
 *           4. Remove stopwords comuns e palavras curtas (< 3 caracteres)
 *           5. Retorna lista de palavras filtradas
 * Input: text (string) - Texto a tokenizar
 * Output: []string - Lista de palavras tokenizadas e filtradas
 * Por que faz: A tokenização é essencial para o Naive Bayes, que opera em
 *              palavras individuais. Remover stopwords e caracteres especiais
 *              melhora a qualidade da análise.
 */
func tokenize(text string) []string {
	// Converter para minúsculas
	text = strings.ToLower(text)

	// Remover caracteres especiais, manter apenas alfanuméricos e espaços
	re := regexp.MustCompile(`[^a-z0-9\s]`)
	text = re.ReplaceAllString(text, " ")

	// Dividir em espaços em branco
	words := strings.Fields(text)

	// Remover stopwords e palavras curtas
	stopWords := map[string]bool{
		"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
		"be": true, "by": true, "for": true, "from": true, "has": true, "he": true,
		"in": true, "is": true, "it": true, "its": true, "of": true, "on": true,
		"that": true, "the": true, "to": true, "was": true, "will": true, "with": true,
	}

	var filtered []string
	for _, word := range words {
		if len(word) > 2 && !stopWords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// ============================================================================
// FUNÇÕES DE ESTATÍSTICAS
// ============================================================================

/*
 * Função: generateStats
 * Descrição: Gera e exibe estatísticas comparando os dados originais com os reclassificados
 * Objetivo: Fornecer feedback sobre o impacto da reclassificação, mostrando
 *           quantos CVEs foram alterados e quais vetores foram mais adicionados
 * Como faz: 1. Compara cada CVE original com sua versão reclassificada
 *           2. Conta quantos CVEs tiveram alterações nos vetores de ataque
 *           3. Rastreia quais vetores foram adicionados (não estavam no original)
 *           4. Calcula percentuais de mudança
 *           5. Ordena os vetores por frequência de adição
 *           6. Exibe os top 10 vetores mais adicionados
 * Input: original ([]CVEEntry) - Dados originais
 *        reclassified ([]CVEEntry) - Dados reclassificados
 * Output: Nenhum (void) - Imprime estatísticas no console
 * Por que faz: As estatísticas ajudam a avaliar o impacto da reclassificação,
 *              identificar tendências e validar que as mudanças fazem sentido.
 */
func generateStats(original, reclassified []CVEEntry) {
	// Contar mudanças
	changed := 0
	vectorChanges := make(map[string]int)

	for i := 0; i < len(original); i++ {
		origVectors := original[i].AttackVectors
		newVectors := reclassified[i].AttackVectors

		if !equalSlices(origVectors, newVectors) {
			changed++

			// Rastrear quais vetores foram adicionados/removidos
			for _, v := range newVectors {
				if !contains(origVectors, v) {
					vectorChanges[v]++
				}
			}
		}
	}

	fmt.Printf("Total CVEs: %d\n", len(original))
	fmt.Printf("Changed: %d (%.1f%%)\n", changed, float64(changed)*100/float64(len(original)))
	fmt.Printf("Unchanged: %d (%.1f%%)\n\n", len(original)-changed, float64(len(original)-changed)*100/float64(len(original)))

	// Top mudanças de vetor
	type vectorChange struct {
		vector string
		count  int
	}

	var changes []vectorChange
	for v, c := range vectorChanges {
		changes = append(changes, vectorChange{v, c})
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].count > changes[j].count
	})

	fmt.Println("Top 10 newly added attack vectors:")
	for i := 0; i < 10 && i < len(changes); i++ {
		fmt.Printf("  %d. %s: %d CVEs\n", i+1, changes[i].vector, changes[i].count)
	}
}

/*
 * Função: equalSlices
 * Descrição: Verifica se dois slices de strings contêm os mesmos elementos
 *            (independente da ordem)
 * Objetivo: Comparar vetores de ataque originais com reclassificados
 * Como faz: 1. Verifica se os tamanhos são diferentes (retorna false)
 *           2. Cria um mapa dos elementos do primeiro slice
 *           3. Verifica se todos os elementos do segundo slice estão no mapa
 *           4. Retorna true se todos estiverem presentes, false caso contrário
 * Input: a, b ([]string) - Dois slices a comparar
 * Output: bool - true se contêm os mesmos elementos, false caso contrário
 * Por que faz: Necessário para detectar mudanças nos vetores de ataque durante
 *              a reclassificação, independente da ordem dos elementos.
 */
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]bool)
	for _, v := range a {
		aMap[v] = true
	}

	for _, v := range b {
		if !aMap[v] {
			return false
		}
	}

	return true
}

/*
 * Função: contains
 * Descrição: Verifica se um slice contém um item específico
 * Objetivo: Função auxiliar para verificar presença de elementos em slices
 * Como faz: Itera pelo slice e compara cada elemento com o item procurado
 * Input: slice ([]string) - Slice a verificar
 *        item (string) - Item a procurar
 * Output: bool - true se o item está presente, false caso contrário
 * Por que faz: Função auxiliar usada para detectar quais vetores foram adicionados
 *              durante a reclassificação.
 */
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
