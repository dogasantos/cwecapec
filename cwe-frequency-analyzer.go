package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// ============================================================================
// ESTRUTURAS DE DADOS
// ============================================================================

// CVEEntry representa um registro individual de CVE do dataset de treinamento,
// contendo todas as informações necessárias para análise de frequência
type CVEEntry struct {
	CVEID         string   `json:"cve_id"`         // ID do CVE (ex: "CVE-2024-12345")
	Description   string   `json:"description"`    // Descrição textual da vulnerabilidade
	CWEs          []string `json:"cwes"`           // Lista de IDs de CWE associados (ex: ["89", "20"])
	AttackVectors []string `json:"attack_vectors"` // Vetores de ataque classificados (ex: ["sql_injection"])
	PublishedDate string   `json:"published_date"` // Data de publicação do CVE
}

// CWEFrequency representa as estatísticas de frequência de um CWE específico,
// incluindo contagem absoluta, percentual e ranking
type CWEFrequency struct {
	CWEID      string  `json:"cwe_id"`     // ID do CWE (ex: "89")
	Count      int     `json:"count"`      // Número absoluto de ocorrências
	Percentage float64 `json:"percentage"` // Percentual em relação ao total (0-100)
	Rank       int     `json:"rank"`       // Posição no ranking (1 = mais frequente)
}

// VectorStats contém estatísticas agregadas de CWEs para um vetor de ataque específico,
// incluindo contagens totais, frequências calculadas e lista dos CWEs mais comuns
type VectorStats struct {
	TotalCVEs      int            `json:"total_cves"`      // Total de CVEs classificados neste vetor
	CWEFrequencies []CWEFrequency `json:"cwe_frequencies"` // Lista completa de CWEs ordenada por frequência
	TopCWEs        []string       `json:"top_cwes"`        // IDs dos top 10 CWEs mais frequentes
	CWECounts      map[string]int `json:"cwe_counts"`      // Mapa completo de CWE -> contagem bruta
}

// CWEFrequencyMap é a estrutura de saída completa que contém todas as estatísticas
// de frequência de CWEs, tanto globais quanto por vetor de ataque
type CWEFrequencyMap struct {
	GeneratedAt   string                  `json:"generated_at"`    // Timestamp de geração
	TotalCVEs     int                     `json:"total_cves"`      // Total de CVEs analisados
	AttackVectors map[string]*VectorStats `json:"attack_vectors"`  // Estatísticas por vetor de ataque
	GlobalTopCWEs []CWEFrequency          `json:"global_top_cwes"` // CWEs mais frequentes em todos os vetores
}

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

/*
 * Função: main
 * Descrição: Ponto de entrada do programa que orquestra a análise completa de
 *            frequências de CWEs nos dados de treinamento
 * Objetivo: Gerar um mapa estatístico detalhado mostrando quais CWEs são mais comuns
 *           para cada vetor de ataque, permitindo entender a distribuição real de
 *           fraquezas no dataset e otimizar os mapeamentos de classificação
 * Como faz: 1. Carrega o arquivo de dados de treinamento (training_data.json)
 *           2. Analisa as frequências de CWEs globalmente e por vetor de ataque
 *           3. Calcula estatísticas (contagens, percentuais, rankings)
 *           4. Exibe um relatório detalhado no console
 *           5. Salva o mapa completo de frequências em JSON
 * Input: Arquivo resources/training_data.json (gerado pelo phase1-collector)
 * Output: Arquivo resources/cwe_frequency_map.json (mapa de frequências completo)
 *         e relatório estatístico no console
 * Por que faz: Compreender a distribuição de CWEs é essencial para:
 *              - Criar mapeamentos otimizados de vetor de ataque para CWE
 *              - Identificar quais CWEs são mais prevalentes no mundo real
 *              - Priorizar análises de segurança baseadas em frequência
 *              - Validar a qualidade dos dados de treinamento
 */
func main() {
	fmt.Println("=================================================================")
	fmt.Println("CWE Frequency Analyzer")
	fmt.Println("Generates statistical CWE frequency map from training data")
	fmt.Println("=================================================================\n")

	resourcesPath := "resources"
	inputPath := resourcesPath + "/training_data.json"
	outputPath := resourcesPath + "/cwe_frequency_map.json"

	// Carregar os dados de treinamento
	fmt.Printf("Loading training data from %s... ", inputPath)
	trainingData, err := loadTrainingData(inputPath)
	if err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ (%d CVEs loaded)\n\n", len(trainingData))

	// Analisar as frequências de CWEs
	fmt.Println("Analyzing CWE frequencies by attack vector...")
	frequencyMap := analyzeFrequencies(trainingData)

	// Exibir estatísticas no console
	displayStatistics(frequencyMap)

	// Salvar os resultados em arquivo JSON
	fmt.Printf("\nSaving frequency map to %s... ", outputPath)
	if err := saveFrequencyMap(frequencyMap, outputPath); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	fmt.Println("\n=================================================================")
	fmt.Println("Analysis complete!")
	fmt.Println("=================================================================")
}

// ============================================================================
// FUNÇÕES DE CARREGAMENTO DE DADOS
// ============================================================================

/*
 * Função: loadTrainingData
 * Descrição: Carrega e desserializa o arquivo JSON contendo os dados de treinamento
 *            de CVEs com suas classificações de CWE e vetores de ataque
 * Objetivo: Ler o dataset de treinamento gerado pelo phase1-collector e convertê-lo
 *           em uma estrutura de dados Go para análise estatística
 * Como faz: 1. Abre o arquivo especificado pelo caminho
 *           2. Lê todo o conteúdo do arquivo em memória
 *           3. Desserializa o JSON para um slice de CVEEntry
 *           4. Retorna o slice de entradas ou erro em caso de falha
 * Input: path (string) - Caminho completo para o arquivo training_data.json
 * Output: ([]CVEEntry, error) - Slice contendo todos os registros de CVE carregados,
 *         ou erro se houver falha na leitura/parsing
 * Por que faz: Os dados de treinamento são a fonte primária para análise de frequências.
 *              Este arquivo contém milhares de CVEs reais com seus CWEs associados,
 *              permitindo calcular estatísticas representativas da prevalência de
 *              diferentes tipos de vulnerabilidades no mundo real.
 */
func loadTrainingData(path string) ([]CVEEntry, error) {
	// Abrir o arquivo de dados de treinamento
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Ler todo o conteúdo do arquivo
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Desserializar JSON para slice de CVEEntry
	var entries []CVEEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}

	return entries, nil
}

// ============================================================================
// FUNÇÕES DE ANÁLISE ESTATÍSTICA
// ============================================================================

/*
 * Função: analyzeFrequencies
 * Descrição: Realiza a análise completa de frequências de CWEs, processando todos
 *            os registros de CVE e calculando estatísticas globais e por vetor de ataque
 * Objetivo: Gerar um mapa estatístico abrangente que mostre:
 *           - Quais CWEs são mais comuns em cada vetor de ataque
 *           - Quantos CVEs estão associados a cada CWE
 *           - Percentuais e rankings de prevalência
 *           - Estatísticas globais agregadas
 * Como faz: 1. Inicializa a estrutura de saída (CWEFrequencyMap)
 *           2. Cria mapas de contagem para rastrear frequências globais e por vetor
 *           3. Itera por todos os CVEs do dataset:
 *              a. Incrementa contadores globais para cada CWE encontrado
 *              b. Para cada vetor de ataque do CVE:
 *                 - Cria estatísticas do vetor se não existir
 *                 - Incrementa o contador de CVEs do vetor
 *                 - Incrementa contadores de CWE específicos do vetor
 *           4. Calcula frequências e rankings para cada vetor de ataque
 *           5. Extrai os top 10 CWEs de cada vetor
 *           6. Calcula frequências globais agregadas
 *           7. Retorna o mapa completo de frequências
 * Input: entries ([]CVEEntry) - Slice contendo todos os registros de CVE do dataset
 * Output: *CWEFrequencyMap - Ponteiro para a estrutura completa contendo:
 *         - Estatísticas por vetor de ataque (contagens, percentuais, rankings)
 *         - Lista dos top CWEs para cada vetor
 *         - Estatísticas globais agregadas
 *         - Timestamp de geração
 * Por que faz: Esta é a função central de análise que transforma dados brutos de CVE
 *              em estatísticas acionáveis. Os resultados permitem:
 *              - Criar mapeamentos otimizados de vetor para CWE
 *              - Priorizar análises de segurança baseadas em prevalência real
 *              - Validar a qualidade e representatividade dos dados de treinamento
 *              - Identificar tendências em tipos de vulnerabilidades
 */
func analyzeFrequencies(entries []CVEEntry) *CWEFrequencyMap {
	// Inicializar a estrutura de saída
	frequencyMap := &CWEFrequencyMap{
		GeneratedAt:   fmt.Sprintf("%v", os.Getenv("TZ")), // Timestamp de geração
		TotalCVEs:     len(entries),
		AttackVectors: make(map[string]*VectorStats),
	}

	// Rastrear contagens globais de CWE (agregadas de todos os vetores)
	globalCWECounts := make(map[string]int)

	// Processar cada CVE do dataset
	for _, entry := range entries {
		// Incrementar contadores globais para cada CWE deste CVE
		for _, cweID := range entry.CWEs {
			globalCWECounts[cweID]++
		}

		// Processar cada vetor de ataque associado a este CVE
		for _, vector := range entry.AttackVectors {
			// Criar estatísticas do vetor se ainda não existir
			if _, exists := frequencyMap.AttackVectors[vector]; !exists {
				frequencyMap.AttackVectors[vector] = &VectorStats{
					CWECounts: make(map[string]int),
				}
			}

			// Obter referência às estatísticas do vetor
			stats := frequencyMap.AttackVectors[vector]

			// Incrementar contador de CVEs deste vetor
			stats.TotalCVEs++

			// Incrementar contadores de CWE específicos deste vetor
			for _, cweID := range entry.CWEs {
				stats.CWECounts[cweID]++
			}
		}
	}

	// Calcular frequências e rankings para cada vetor de ataque
	for _, stats := range frequencyMap.AttackVectors {
		// Calcular percentuais e criar lista ordenada de frequências
		stats.CWEFrequencies = calculateFrequencies(stats.CWECounts, stats.TotalCVEs)

		// Extrair os IDs dos top 10 CWEs mais frequentes
		stats.TopCWEs = getTopCWEs(stats.CWEFrequencies, 10)
	}

	// Calcular estatísticas globais (agregadas de todos os vetores)
	frequencyMap.GlobalTopCWEs = calculateFrequencies(globalCWECounts, len(entries))

	return frequencyMap
}

/*
 * Função: calculateFrequencies
 * Descrição: Converte um mapa de contagens brutas de CWE em uma lista estruturada
 *            de frequências com percentuais e rankings
 * Objetivo: Transformar contagens absolutas em estatísticas mais úteis e interpretáveis,
 *           incluindo percentuais relativos e posições de ranking ordenadas
 * Como faz: 1. Cria um slice vazio para armazenar as frequências
 *           2. Para cada CWE no mapa de contagens:
 *              a. Calcula o percentual: (contagem / total) * 100
 *              b. Cria uma estrutura CWEFrequency com ID, contagem e percentual
 *              c. Adiciona ao slice de frequências
 *           3. Ordena o slice por contagem (ordem decrescente)
 *           4. Atribui rankings baseados na posição ordenada (1 = mais frequente)
 *           5. Retorna o slice ordenado e ranqueado
 * Input: cweCounts (map[string]int) - Mapa de CWE ID para contagem bruta
 *        totalCVEs (int) - Total de CVEs para calcular percentuais
 * Output: []CWEFrequency - Slice ordenado de frequências contendo:
 *         - ID do CWE
 *         - Contagem absoluta
 *         - Percentual relativo (0-100)
 *         - Ranking (1 = mais frequente)
 * Por que faz: Percentuais e rankings são mais úteis que contagens brutas para:
 *              - Comparar prevalência entre diferentes vetores de ataque
 *              - Identificar rapidamente os CWEs mais críticos
 *              - Gerar relatórios e visualizações compreensíveis
 *              - Tomar decisões de priorização baseadas em dados
 */
func calculateFrequencies(cweCounts map[string]int, totalCVEs int) []CWEFrequency {
	var frequencies []CWEFrequency

	// Converter contagens brutas em estruturas de frequência com percentuais
	for cweID, count := range cweCounts {
		// Calcular percentual: (contagem / total) * 100
		percentage := float64(count) * 100.0 / float64(totalCVEs)

		frequencies = append(frequencies, CWEFrequency{
			CWEID:      cweID,
			Count:      count,
			Percentage: percentage,
		})
	}

	// Ordenar por contagem em ordem decrescente (mais frequente primeiro)
	sort.Slice(frequencies, func(i, j int) bool {
		return frequencies[i].Count > frequencies[j].Count
	})

	// Atribuir rankings baseados na posição ordenada
	for i := range frequencies {
		frequencies[i].Rank = i + 1 // Rank 1 = mais frequente
	}

	return frequencies
}

/*
 * Função: getTopCWEs
 * Descrição: Extrai os IDs dos N CWEs mais frequentes de uma lista de frequências
 * Objetivo: Criar uma lista simplificada contendo apenas os IDs dos CWEs mais relevantes,
 *           útil para consultas rápidas e mapeamentos simplificados
 * Como faz: 1. Cria um slice vazio para armazenar os IDs
 *           2. Itera pelos primeiros N elementos da lista de frequências
 *           3. Extrai o ID de cada CWE e adiciona ao slice
 *           4. Para se a lista acabar antes de atingir N elementos
 *           5. Retorna o slice de IDs
 * Input: frequencies ([]CWEFrequency) - Lista de frequências ordenada por prevalência
 *        n (int) - Número de top CWEs a extrair (ex: 10)
 * Output: []string - Slice contendo os IDs dos N CWEs mais frequentes
 *         Exemplo: ["79", "89", "20", "787", "416"] para top 5
 * Por que faz: Muitas operações precisam apenas dos IDs dos CWEs mais comuns,
 *              sem as estatísticas detalhadas. Esta função facilita a criação
 *              de listas simplificadas para mapeamentos rápidos e consultas eficientes.
 */
func getTopCWEs(frequencies []CWEFrequency, n int) []string {
	var topCWEs []string

	// Extrair os IDs dos primeiros N CWEs (já ordenados por frequência)
	for i := 0; i < n && i < len(frequencies); i++ {
		topCWEs = append(topCWEs, frequencies[i].CWEID)
	}

	return topCWEs
}

// ============================================================================
// FUNÇÕES DE PERSISTÊNCIA
// ============================================================================

/*
 * Função: saveFrequencyMap
 * Descrição: Serializa e salva o mapa completo de frequências em um arquivo JSON
 *            formatado e legível
 * Objetivo: Persistir todas as estatísticas calculadas em disco para que possam ser
 *           consumidas por outros componentes da pipeline (como o cwe-vector-mapper)
 *           sem necessidade de reprocessar os dados de treinamento
 * Como faz: 1. Cria (ou sobrescreve) o arquivo de saída
 *           2. Configura o encoder JSON com indentação de 2 espaços
 *           3. Serializa a estrutura CWEFrequencyMap completa para JSON
 *           4. Escreve o JSON formatado no arquivo
 * Input: frequencyMap (*CWEFrequencyMap) - Ponteiro para o mapa de frequências completo
 *        path (string) - Caminho onde o arquivo JSON será salvo
 * Output: error - nil se a operação foi bem-sucedida, ou erro descrevendo a falha
 * Por que faz: O mapa de frequências é usado por múltiplos componentes da pipeline:
 *              - cwe-vector-mapper: cria mapeamentos simplificados
 *              - Análises manuais: inspeção de estatísticas
 *              - Validação de qualidade: verificação de distribuição de dados
 *              Persistir em JSON permite reutilização sem reprocessamento.
 */
func saveFrequencyMap(frequencyMap *CWEFrequencyMap, path string) error {
	// Criar o arquivo de saída (sobrescreve se já existir)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Configurar o encoder JSON com indentação para legibilidade
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // 2 espaços de indentação

	// Serializar e escrever o mapa no arquivo
	return encoder.Encode(frequencyMap)
}

// ============================================================================
// FUNÇÕES DE EXIBIÇÃO
// ============================================================================

/*
 * Função: displayStatistics
 * Descrição: Exibe um relatório estatístico completo e formatado no console,
 *            mostrando estatísticas globais e por vetor de ataque
 * Objetivo: Fornecer feedback visual imediato sobre os resultados da análise,
 *           permitindo que o usuário compreenda rapidamente:
 *           - Quais CWEs são mais comuns globalmente
 *           - Quais vetores de ataque têm mais CVEs
 *           - Quais CWEs são mais prevalentes em cada vetor
 * Como faz: 1. Exibe estatísticas globais:
 *              a. Total de CVEs analisados
 *              b. Número de vetores de ataque encontrados
 *              c. Top 20 CWEs mais comuns (com contagens e percentuais)
 *           2. Exibe estatísticas por vetor de ataque:
 *              a. Ordena vetores por número de CVEs (ordem decrescente)
 *              b. Exibe os top 15 vetores de ataque
 *              c. Para cada vetor, mostra os top 5 CWEs mais frequentes
 *           3. Formata a saída com alinhamento e símbolos visuais
 * Input: frequencyMap (*CWEFrequencyMap) - Ponteiro para o mapa de frequências completo
 * Output: Nenhum (void) - A função apenas imprime no stdout
 * Por que faz: A análise de frequências gera muitos dados. Este relatório formatado
 *              permite que o usuário:
 *              - Valide rapidamente se a análise foi bem-sucedida
 *              - Identifique tendências e padrões nos dados
 *              - Detecte anomalias ou problemas de qualidade
 *              - Compreenda a distribuição de vulnerabilidades sem abrir o JSON
 */
func displayStatistics(frequencyMap *CWEFrequencyMap) {
	// ========================================================================
	// SEÇÃO 1: ESTATÍSTICAS GLOBAIS
	// ========================================================================
	fmt.Println("\n=================================================================")
	fmt.Println("Global Statistics")
	fmt.Println("=================================================================")
	fmt.Printf("Total CVEs analyzed: %d\n", frequencyMap.TotalCVEs)
	fmt.Printf("Attack vectors found: %d\n\n", len(frequencyMap.AttackVectors))

	// Exibir os top 20 CWEs mais comuns em todo o dataset
	fmt.Println("Top 20 CWEs (across all attack vectors):")
	for i := 0; i < 20 && i < len(frequencyMap.GlobalTopCWEs); i++ {
		cwe := frequencyMap.GlobalTopCWEs[i]
		// Formato: "  1. CWE-79:  1234 CVEs (12.34%)"
		fmt.Printf("  %2d. CWE-%s: %5d CVEs (%.2f%%)\n",
			cwe.Rank, cwe.CWEID, cwe.Count, cwe.Percentage)
	}

	// ========================================================================
	// SEÇÃO 2: ESTATÍSTICAS POR VETOR DE ATAQUE
	// ========================================================================
	fmt.Println("\n=================================================================")
	fmt.Println("Attack Vector Statistics")
	fmt.Println("=================================================================")

	// Estrutura auxiliar para ordenar vetores por contagem de CVEs
	type vectorCount struct {
		vector string
		count  int
	}

	// Coletar todos os vetores com suas contagens
	var vectors []vectorCount
	for vector, stats := range frequencyMap.AttackVectors {
		vectors = append(vectors, vectorCount{vector, stats.TotalCVEs})
	}

	// Ordenar vetores por contagem de CVEs (ordem decrescente)
	sort.Slice(vectors, func(i, j int) bool {
		return vectors[i].count > vectors[j].count
	})

	// Exibir os top 15 vetores de ataque com seus CWEs mais comuns
	fmt.Println("\nTop 15 attack vectors by CVE count:")
	for i := 0; i < 15 && i < len(vectors); i++ {
		vc := vectors[i]
		stats := frequencyMap.AttackVectors[vc.vector]

		// Cabeçalho do vetor: "1. sql_injection (1234 CVEs)"
		fmt.Printf("\n%2d. %s (%d CVEs)\n", i+1, vc.vector, vc.count)
		fmt.Println("    Top 5 CWEs:")

		// Exibir os top 5 CWEs deste vetor
		for j := 0; j < 5 && j < len(stats.CWEFrequencies); j++ {
			cwe := stats.CWEFrequencies[j]
			// Formato: "      - CWE-89: 456 CVEs (45.6%)"
			fmt.Printf("      - CWE-%s: %d CVEs (%.1f%%)\n",
				cwe.CWEID, cwe.Count, cwe.Percentage)
		}
	}
}
