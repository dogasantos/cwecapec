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

// ============================================================================
// ESTRUTURAS DE DADOS
// ============================================================================

// CVETrainingExample representa um exemplo de treinamento do dataset
type CVETrainingExample struct {
	CVEID         string   `json:"cve_id"`         // ID do CVE
	Description   string   `json:"description"`    // Descrição textual
	CWEIDs        []string `json:"cwes"`           // IDs de CWE associados
	AttackVectors []string `json:"attack_vectors"` // Vetores de ataque classificados
}

// PatternRule representa uma regra de padrão com palavras-chave e métricas
type PatternRule struct {
	Keywords    []string `json:"keywords"`    // Lista de palavras-chave do padrão
	Specificity float64  `json:"specificity"` // Especificidade (0-1): quão específico é para este vetor
	Boost       float64  `json:"boost"`       // Multiplicador de pontuação (0.1-5.0)
	Support     int      `json:"support"`     // Número de CVEs que contêm este padrão
}

// PatternTaxonomy é a estrutura de saída completa contendo todos os padrões
type PatternTaxonomy struct {
	Patterns map[string][]PatternRule `json:"patterns"` // vetor_ataque -> lista de regras
	Stats    TaxonomyStats            `json:"stats"`    // Estatísticas da taxonomia
}

// TaxonomyStats contém estatísticas agregadas da taxonomia
type TaxonomyStats struct {
	TotalVectors  int                      `json:"total_vectors"`           // Total de vetores de ataque
	TotalPatterns int                      `json:"total_patterns"`          // Total de padrões gerados
	VectorCounts  map[string]int           `json:"vector_counts"`           // Contagem de CVEs por vetor
	TopPatterns   map[string][]PatternRule `json:"top_patterns_per_vector"` // Top 5 padrões de cada vetor
}

// TermScore representa a pontuação de um termo para análise TF-IDF
type TermScore struct {
	Term        string  // Termo (palavra-chave)
	TF          float64 // Frequência do termo (normalizada)
	IDF         float64 // Frequência inversa de documento
	TFIDF       float64 // Pontuação TF-IDF
	Specificity float64 // Especificidade para o vetor (0-1)
	Support     int     // Número de CVEs contendo este termo
}

// ============================================================================
// CONFIGURAÇÃO
// ============================================================================

const (
	TrainingDataPath    = "resources/training_data.json"    // Caminho dos dados de treinamento
	PatternTaxonomyPath = "resources/pattern_taxonomy.json" // Caminho de saída da taxonomia

	MinTermFrequency     = 3   // Termo deve aparecer pelo menos 3 vezes em um vetor
	MinSpecificity       = 0.6 // Termo deve ser pelo menos 60% específico para o vetor
	MaxPatternsPerVector = 15  // Manter os top 15 padrões por vetor
	MinPatternLength     = 3   // Comprimento mínimo da palavra-chave
)

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

/*
 * Função: main
 * Descrição: Ponto de entrada do programa que orquestra a geração da taxonomia
 *            de padrões de vetores de ataque a partir dos dados de treinamento
 * Objetivo: Criar um arquivo JSON contendo padrões discriminativos (palavras-chave)
 *           para cada vetor de ataque, permitindo detecção rápida e precisa de
 *           vetores através de correspondência de padrões
 * Como faz: 1. Carrega os dados de treinamento (training_data.json)
 *           2. Extrai termos discriminativos por vetor usando TF-IDF
 *           3. Calcula especificidade e pontuações de boost
 *           4. Adiciona padrões críticos manuais (deserialization, JNDI, SQL, etc.)
 *           5. Salva a taxonomia completa em JSON
 *           6. Exibe sumário estatístico
 * Input: Arquivo resources/training_data.json (gerado pelo phase1-collector)
 * Output: Arquivo resources/pattern_taxonomy.json contendo:
 *         - Padrões de palavras-chave para cada vetor de ataque
 *         - Métricas de especificidade e boost
 *         - Estatísticas agregadas
 * Por que faz: Padrões de palavras-chave fornecem uma camada de classificação
 *              rápida e precisa. Ao extrair automaticamente padrões dos dados
 *              de treinamento usando TF-IDF, criamos regras baseadas em evidências
 *              que complementam o Naive Bayes e a hierarquia CWE.
 */
func main() {
	fmt.Println("Generating Attack Vector Pattern Taxonomy from Training Data")
	fmt.Println(strings.Repeat("=", 70))

	// Passo 1: Carregar dados de treinamento
	fmt.Println("\n[1/4] Loading CVE training data...")
	trainingData, err := loadTrainingData(TrainingDataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading training data: %v\n", err)
		fmt.Println("Run phase1-collector first to generate training data")
		os.Exit(1)
	}
	fmt.Printf("  Loaded %d CVE examples\n", len(trainingData))

	// Passo 2: Extrair termos discriminativos por vetor de ataque
	fmt.Println("\n[2/4] Extracting discriminative terms per attack vector...")
	taxonomy := buildPatternTaxonomy(trainingData)
	fmt.Printf("  Generated patterns for %d attack vectors\n", len(taxonomy.Patterns))

	// Passo 3: Calcular especificidade e pontuações de boost
	fmt.Println("\n[3/4] Calculating specificity and boost scores...")
	calculateBoostScores(taxonomy, trainingData)

	// Passo 4: Salvar taxonomia
	fmt.Println("\n[4/4] Saving pattern taxonomy...")
	if err := saveJSON(PatternTaxonomyPath, taxonomy); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving taxonomy: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Saved to %s\n", PatternTaxonomyPath)

	// Exibir sumário
	displaySummary(taxonomy)

	fmt.Println("\nPattern taxonomy generated successfully!")
	fmt.Println("Use this file in phase3-classifier.go for data-driven pattern boosting")
}

// ============================================================================
// FUNÇÕES DE CARREGAMENTO DE DADOS
// ============================================================================

/*
 * Função: loadTrainingData
 * Descrição: Carrega os dados de treinamento do arquivo JSON
 * Objetivo: Ler o dataset de CVEs com suas classificações de vetores de ataque
 * Como faz: 1. Lê o arquivo completo em memória
 *           2. Desserializa o JSON para slice de CVETrainingExample
 *           3. Retorna o slice ou erro
 * Input: path (string) - Caminho para o arquivo training_data.json
 * Output: ([]CVETrainingExample, error) - Slice de exemplos ou erro
 * Por que faz: Os dados de treinamento são a fonte primária para extração de padrões.
 */
func loadTrainingData(path string) ([]CVETrainingExample, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var trainingData []CVETrainingExample
	if err := json.Unmarshal(data, &trainingData); err != nil {
		return nil, err
	}

	return trainingData, nil
}

// ============================================================================
// FUNÇÕES DE CONSTRUÇÃO DA TAXONOMIA DE PADRÕES
// ============================================================================

/*
 * Função: buildPatternTaxonomy
 * Descrição: Constrói a taxonomia completa de padrões extraindo termos discriminativos
 *            de cada vetor de ataque usando análise TF-IDF
 * Objetivo: Identificar automaticamente palavras-chave que são altamente específicas
 *           para cada vetor de ataque, criando padrões baseados em evidências
 * Como faz: 1. Agrupa CVEs por vetor de ataque
 *           2. Para cada vetor:
 *              a. Calcula frequência de termos (TF) no vetor
 *              b. Calcula frequência inversa de documento (IDF) global
 *              c. Calcula pontuação TF-IDF para cada termo
 *              d. Calcula especificidade (% de ocorrências neste vetor)
 *              e. Filtra termos com baixa frequência ou especificidade
 *              f. Ordena por TF-IDF (descendente)
 *              g. Seleciona os top N termos como padrões
 *           3. Adiciona padrões críticos manuais (JNDI, SQL injection, etc.)
 *           4. Calcula estatísticas agregadas
 * Input: trainingData ([]CVETrainingExample) - Dataset de treinamento completo
 * Output: *PatternTaxonomy - Taxonomia completa com padrões para cada vetor
 * Por que faz: TF-IDF é uma técnica clássica de recuperação de informação que
 *              identifica termos que são:
 *              - Frequentes em um vetor específico (TF alto)
 *              - Raros no dataset geral (IDF alto)
 *              Isso garante que os padrões sejam discriminativos e específicos.
 */
func buildPatternTaxonomy(trainingData []CVETrainingExample) *PatternTaxonomy {
	// Agrupar CVEs por vetor de ataque
	vectorCVEs := make(map[string][]string) // vetor -> descrições de CVE
	vectorCounts := make(map[string]int)

	for _, example := range trainingData {
		for _, vector := range example.AttackVectors {
			vectorCVEs[vector] = append(vectorCVEs[vector], example.Description)
			vectorCounts[vector]++
		}
	}

	// Extrair termos discriminativos para cada vetor
	taxonomy := &PatternTaxonomy{
		Patterns: make(map[string][]PatternRule),
		Stats: TaxonomyStats{
			TotalVectors: len(vectorCVEs),
			VectorCounts: vectorCounts,
			TopPatterns:  make(map[string][]PatternRule),
		},
	}

	// Calcular TF-IDF para cada vetor
	docFreq := calculateDocumentFrequency(trainingData)
	totalDocs := float64(len(trainingData))

	for vector, descriptions := range vectorCVEs {
		// Calcular frequência de termos para este vetor
		termFreq := make(map[string]int)
		for _, desc := range descriptions {
			terms := tokenize(desc)
			for _, term := range terms {
				termFreq[term]++
			}
		}

		// Calcular pontuações TF-IDF
		termScores := make([]TermScore, 0)
		for term, tf := range termFreq {
			// Filtrar termos com baixa frequência
			if tf < MinTermFrequency {
				continue
			}

			// TF (normalizado pelo tamanho do vetor)
			tfNorm := float64(tf) / float64(len(descriptions))

			// IDF (frequência inversa de documento)
			df := float64(docFreq[term])
			idf := math.Log(totalDocs / (1.0 + df))

			// TF-IDF (produto de TF e IDF)
			tfidf := tfNorm * idf

			// Especificidade: com que frequência este termo aparece neste vetor vs outros
			termInVector := float64(tf)
			termTotal := float64(docFreq[term])
			specificity := termInVector / termTotal

			// Filtrar termos com baixa especificidade
			if specificity >= MinSpecificity {
				termScores = append(termScores, TermScore{
					Term:        term,
					TF:          tfNorm,
					IDF:         idf,
					TFIDF:       tfidf,
					Specificity: specificity,
					Support:     tf,
				})
			}
		}

		// Ordenar por pontuação TF-IDF (descendente)
		sort.Slice(termScores, func(i, j int) bool {
			return termScores[i].TFIDF > termScores[j].TFIDF
		})

		// Criar regras de padrão dos top termos
		patterns := make([]PatternRule, 0)
		topN := min(MaxPatternsPerVector, len(termScores))

		for i := 0; i < topN; i++ {
			ts := termScores[i]

			// Padrão de palavra-chave única
			pattern := PatternRule{
				Keywords:    []string{ts.Term},
				Specificity: ts.Specificity,
				Boost:       0.0, // Será calculado depois
				Support:     ts.Support,
			}
			patterns = append(patterns, pattern)
		}

		taxonomy.Patterns[vector] = patterns
		taxonomy.Stats.TopPatterns[vector] = patterns[:min(5, len(patterns))]
	}

	// Adicionar padrões críticos manuais para casos importantes conhecidos
	addManualCriticalPatterns(taxonomy)

	taxonomy.Stats.TotalPatterns = countTotalPatterns(taxonomy)

	return taxonomy
}

/*
 * Função: addManualCriticalPatterns
 * Descrição: Adiciona padrões críticos curados manualmente para casos importantes
 *            que podem não aparecer frequentemente nos dados de treinamento
 * Objetivo: Garantir que padrões críticos de alta confiança (como JNDI, LDAP para
 *           desserialização) estejam sempre presentes, mesmo que raros no dataset
 * Como faz: 1. Define padrões manuais para vetores críticos:
 *              - deserialization: jndi, ldap, lookup, unmarsh, pickle
 *              - jndi_injection: jndi, ldap, naming
 *              - sql_injection: union+select, or+=
 *           2. Para cada vetor com padrões manuais:
 *              a. Se o vetor já existe, adiciona padrões manuais no início (prioridade)
 *              b. Se não existe, cria nova entrada
 * Input: taxonomy (*PatternTaxonomy) - Taxonomia a ser enriquecida
 * Output: Nenhum (modifica taxonomy in-place)
 * Por que faz: Alguns padrões são críticos mas raros (ex: Log4Shell com JNDI).
 *              Curadoria manual garante que esses casos sejam detectados mesmo
 *              se aparecerem poucas vezes no treinamento.
 */
func addManualCriticalPatterns(taxonomy *PatternTaxonomy) {
	manualPatterns := map[string][]PatternRule{
		"deserialization": {
			{Keywords: []string{"jndi"}, Specificity: 0.95, Boost: 50.0, Support: 100},
			{Keywords: []string{"ldap"}, Specificity: 0.90, Boost: 45.0, Support: 80},
			{Keywords: []string{"lookup"}, Specificity: 0.85, Boost: 40.0, Support: 70},
			{Keywords: []string{"unmarsh"}, Specificity: 0.92, Boost: 48.0, Support: 60},
			{Keywords: []string{"pickle"}, Specificity: 0.94, Boost: 47.0, Support: 50},
		},
		"jndi_injection": {
			{Keywords: []string{"jndi"}, Specificity: 0.95, Boost: 50.0, Support: 100},
			{Keywords: []string{"ldap"}, Specificity: 0.90, Boost: 45.0, Support: 80},
			{Keywords: []string{"naming"}, Specificity: 0.85, Boost: 40.0, Support: 60},
		},
		"sql_injection": {
			{Keywords: []string{"union", "select"}, Specificity: 0.95, Boost: 50.0, Support: 200},
			{Keywords: []string{"or", "="}, Specificity: 0.70, Boost: 30.0, Support: 150},
		},
	}

	// Mesclar padrões manuais com padrões gerados
	for vector, manualRules := range manualPatterns {
		if existingPatterns, exists := taxonomy.Patterns[vector]; exists {
			// Adicionar padrões manuais no início (prioridade mais alta)
			taxonomy.Patterns[vector] = append(manualRules, existingPatterns...)
		} else {
			// Criar nova entrada se o vetor não existir
			taxonomy.Patterns[vector] = manualRules
		}
	}
}

// ============================================================================
// FUNÇÕES DE CÁLCULO DE PONTUAÇÃO DE BOOST
// ============================================================================

/*
 * Função: calculateBoostScores
 * Descrição: Calcula pontuações de boost para cada padrão baseadas em especificidade,
 *            IDF e suporte, calibrando a influência de cada padrão na classificação
 * Objetivo: Atribuir pesos apropriados aos padrões para que:
 *           - Padrões altamente específicos tenham forte influência
 *           - Padrões genéricos tenham influência limitada
 *           - Termos raros recebam boost adicional
 *           - Padrões com mais evidências recebam leve boost
 * Como faz: 1. Para cada padrão em cada vetor:
 *              a. Calcula IDF da primeira palavra-chave
 *              b. Determina boost base pela especificidade:
 *                 - ≥90%: 5.0 (sinal muito forte)
 *                 - ≥80%: 3.0 (sinal bom)
 *                 - ≥70%: 2.0 (sinal decente)
 *                 - ≥60%: 1.0 (sinal fraco)
 *                 - <60%: 0.1 (sinal muito fraco, penalidade)
 *              c. Aplica fator IDF (termos raros recebem 0.5-1.5x)
 *              d. Aplica fator de suporte (mais evidências = até 1.2x)
 *              e. Calcula boost final = base × IDF × suporte
 *              f. Limita boost ao intervalo [0.1, 5.0]
 * Input: taxonomy (*PatternTaxonomy) - Taxonomia com padrões
 *        trainingData ([]CVETrainingExample) - Dataset para calcular IDF
 * Output: Nenhum (modifica taxonomy in-place)
 * Por que faz: O boost controla quanto cada padrão influencia a classificação.
 *              Calibrar corretamente evita que:
 *              - Termos genéricos dominem a classificação
 *              - Padrões específicos sejam ignorados
 *              - Evidências fracas recebam peso excessivo
 */
func calculateBoostScores(taxonomy *PatternTaxonomy, trainingData []CVETrainingExample) {
	// Novo sistema de pontuação:
	// - Alta especificidade (>0.8) + alto suporte → Boost forte (3.0-5.0)
	// - Especificidade média (0.6-0.8) → Boost médio (1.0-3.0)
	// - Baixa especificidade (<0.6) → Boost baixo (0.1-1.0)
	// Isso evita que termos genéricos dominem sinais específicos

	// Calcular frequência de documento para IDF
	docFreq := calculateDocumentFrequency(trainingData)
	totalDocs := float64(len(trainingData))

	for vector, patterns := range taxonomy.Patterns {
		for i := range patterns {
			pattern := &patterns[i]

			// Calcular IDF para a primeira palavra-chave (mais discriminativa)
			var idf float64
			if len(pattern.Keywords) > 0 {
				df := float64(docFreq[pattern.Keywords[0]])
				idf = math.Log(totalDocs / (1.0 + df))
			} else {
				idf = 0.0
			}

			// Boost base pela especificidade
			var baseBoost float64
			if pattern.Specificity >= 0.9 {
				// Muito específico (90%+) → Sinal forte
				baseBoost = 5.0
			} else if pattern.Specificity >= 0.8 {
				// Altamente específico (80-90%) → Bom sinal
				baseBoost = 3.0
			} else if pattern.Specificity >= 0.7 {
				// Moderadamente específico (70-80%) → Sinal decente
				baseBoost = 2.0
			} else if pattern.Specificity >= 0.6 {
				// Algo específico (60-70%) → Sinal fraco
				baseBoost = 1.0
			} else {
				// Baixa especificidade (<60%) → Sinal muito fraco (penalidade)
				baseBoost = 0.1
			}

			// Ajustar por IDF (termos raros recebem boost maior)
			// IDF varia de ~0 (muito comum) a ~8 (muito raro)
			// Normalizar para multiplicador 0.5-1.5
			idfFactor := 0.5 + (idf / 16.0) // Mapeia IDF 0-8 para 0.5-1.0
			if idfFactor > 1.5 {
				idfFactor = 1.5
			}

			// Ajustar por suporte (mais evidências = boost ligeiramente maior)
			// Mas não deixar o suporte dominar (limitar a 1.2x)
			supportFactor := 1.0 + math.Log(float64(pattern.Support)+1.0)/20.0
			if supportFactor > 1.2 {
				supportFactor = 1.2
			}

			// Boost final
			pattern.Boost = baseBoost * idfFactor * supportFactor

			// Limitar ao intervalo [0.1, 5.0]
			if pattern.Boost < 0.1 {
				pattern.Boost = 0.1
			} else if pattern.Boost > 5.0 {
				pattern.Boost = 5.0
			}
		}
		taxonomy.Patterns[vector] = patterns
	}
}

// ============================================================================
// FUNÇÕES DE EXTRAÇÃO DE TERMOS
// ============================================================================

/*
 * Função: extractAllTerms
 * Descrição: Extrai todos os termos únicos do dataset de treinamento
 * Objetivo: Obter o vocabulário completo para análise
 * Como faz: Itera por todos os exemplos, tokeniza descrições e coleta termos únicos
 * Input: trainingData ([]CVETrainingExample) - Dataset completo
 * Output: map[string]bool - Mapa de termos únicos
 * Por que faz: Útil para análise de vocabulário e estatísticas.
 */
func extractAllTerms(trainingData []CVETrainingExample) map[string]bool {
	allTerms := make(map[string]bool)
	for _, example := range trainingData {
		terms := tokenize(example.Description)
		for _, term := range terms {
			allTerms[term] = true
		}
	}
	return allTerms
}

/*
 * Função: calculateDocumentFrequency
 * Descrição: Calcula a frequência de documento (DF) para cada termo no dataset
 * Objetivo: Determinar em quantos documentos (CVEs) cada termo aparece,
 *           necessário para calcular IDF
 * Como faz: 1. Para cada CVE:
 *              a. Tokeniza a descrição
 *              b. Rastreia termos já vistos neste documento (evita contagem dupla)
 *              c. Incrementa DF para cada termo único no documento
 *           2. Retorna mapa de termo → frequência de documento
 * Input: trainingData ([]CVETrainingExample) - Dataset completo
 * Output: map[string]int - Mapa de termo para contagem de documentos
 * Por que faz: DF é usado para calcular IDF = log(total_docs / (1 + DF)).
 *              Termos que aparecem em muitos documentos têm IDF baixo (genéricos).
 *              Termos que aparecem em poucos documentos têm IDF alto (específicos).
 */
func calculateDocumentFrequency(trainingData []CVETrainingExample) map[string]int {
	docFreq := make(map[string]int)

	for _, example := range trainingData {
		terms := tokenize(example.Description)
		seen := make(map[string]bool)

		for _, term := range terms {
			if !seen[term] {
				docFreq[term]++
				seen[term] = true
			}
		}
	}

	return docFreq
}

// ============================================================================
// FUNÇÕES DE TOKENIZAÇÃO
// ============================================================================

/*
 * Função: tokenize
 * Descrição: Tokeniza um texto em palavras individuais, removendo ruído e stopwords
 * Objetivo: Preparar o texto para análise TF-IDF extraindo apenas termos significativos
 * Como faz: 1. Converte para minúsculas
 *           2. Remove números de versão (ex: "1.2.3")
 *           3. Remove IDs de CVE (ex: "CVE-2024-12345")
 *           4. Extrai palavras com 3+ caracteres usando regex
 *           5. Remove stopwords:
 *              a. Stopwords comuns de inglês (the, and, for, etc.)
 *              b. Stopwords específicas de segurança (vulnerability, attacker, etc.)
 *           6. Filtra palavras com menos de MinPatternLength caracteres
 *           7. Retorna lista de termos filtrados
 * Input: text (string) - Texto a tokenizar (descrição de CVE)
 * Output: []string - Lista de termos tokenizados e filtrados
 * Por que faz: Tokenização de qualidade é crítica para TF-IDF. Remover:
 *              - Números de versão: não são discriminativos de vetores de ataque
 *              - Stopwords comuns: aparecem em todos os documentos (IDF baixo)
 *              - Stopwords de segurança: muito genéricas ("vulnerability", "attacker")
 *              Isso garante que apenas termos discriminativos sejam considerados.
 */
func tokenize(text string) []string {
	// Converter para minúsculas
	text = strings.ToLower(text)

	// Remover números de versão e IDs de CVE
	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")
	cveRegex := regexp.MustCompile(`\bcve-\d{4}-\d+\b`)
	text = cveRegex.ReplaceAllString(text, "")

	// Extrair palavras (3+ caracteres)
	wordRegex := regexp.MustCompile(`[a-z]{3,}`)
	words := wordRegex.FindAllString(text, -1)

	// Lista expandida de stopwords (específica para segurança)
	stopwords := map[string]bool{
		// Inglês comum
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"that": true, "this": true, "are": true, "was": true, "were": true,
		"been": true, "being": true, "have": true, "has": true, "had": true,
		"but": true, "not": true, "can": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true,
		"into": true, "through": true, "during": true, "before": true, "after": true,

		// Termos genéricos de segurança (muito comuns para serem discriminativos)
		"vulnerability": true, "allows": true, "attacker": true, "remote": true,
		"via": true, "user": true, "application": true, "system": true,
		"version": true, "versions": true, "prior": true, "component": true,
	}

	filtered := make([]string, 0, len(words))
	for _, word := range words {
		if !stopwords[word] && len(word) >= MinPatternLength {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// ============================================================================
// FUNÇÕES DE EXIBIÇÃO
// ============================================================================

/*
 * Função: displaySummary
 * Descrição: Exibe um sumário estatístico formatado da taxonomia gerada
 * Objetivo: Fornecer feedback visual sobre os resultados da geração de padrões
 * Como faz: 1. Exibe estatísticas globais:
 *              - Total de vetores de ataque
 *              - Total de padrões gerados
 *              - Média de padrões por vetor
 *           2. Exibe top 5 vetores por tamanho do dataset:
 *              - Nome do vetor, contagem de CVEs, número de padrões
 *              - Top 3 padrões de cada vetor com métricas
 *           3. Exibe exemplo detalhado para "deserialization":
 *              - Top 10 padrões com todas as métricas
 * Input: taxonomy (*PatternTaxonomy) - Taxonomia completa gerada
 * Output: Nenhum (imprime no console)
 * Por que faz: O sumário permite validar rapidamente a qualidade da taxonomia:
 *              - Verificar cobertura de vetores
 *              - Inspecionar padrões gerados
 *              - Identificar vetores com poucos padrões
 *              - Validar métricas (especificidade, boost, suporte)
 */
func displaySummary(taxonomy *PatternTaxonomy) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("PATTERN TAXONOMY SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total Attack Vectors:  %d\n", taxonomy.Stats.TotalVectors)
	fmt.Printf("Total Patterns:        %d\n", taxonomy.Stats.TotalPatterns)
	fmt.Printf("Avg Patterns/Vector:   %.1f\n",
		float64(taxonomy.Stats.TotalPatterns)/float64(taxonomy.Stats.TotalVectors))

	// Mostrar top 5 vetores por contagem de padrões
	fmt.Println("\nTop 5 Vectors by Training Data Size:")
	vectorCounts := make([]struct {
		Vector string
		Count  int
	}, 0, len(taxonomy.Stats.VectorCounts))

	for vector, count := range taxonomy.Stats.VectorCounts {
		vectorCounts = append(vectorCounts, struct {
			Vector string
			Count  int
		}{vector, count})
	}

	sort.Slice(vectorCounts, func(i, j int) bool {
		return vectorCounts[i].Count > vectorCounts[j].Count
	})

	for i := 0; i < min(5, len(vectorCounts)); i++ {
		vc := vectorCounts[i]
		patterns := taxonomy.Patterns[vc.Vector]
		fmt.Printf("  %d. %-30s %5d CVEs, %2d patterns\n",
			i+1, vc.Vector, vc.Count, len(patterns))

		// Mostrar top 3 padrões
		for j := 0; j < min(3, len(patterns)); j++ {
			p := patterns[j]
			fmt.Printf("     - %-20s (spec: %.2f, boost: %.1f, support: %d)\n",
				strings.Join(p.Keywords, ", "), p.Specificity, p.Boost, p.Support)
		}
	}

	// Mostrar padrões de exemplo para deserialization
	if patterns, exists := taxonomy.Patterns["deserialization"]; exists {
		fmt.Println("\nExample: Deserialization Patterns (Top 10):")
		for i := 0; i < min(10, len(patterns)); i++ {
			p := patterns[i]
			fmt.Printf("  %2d. %-20s spec=%.2f boost=%.1f support=%d\n",
				i+1, strings.Join(p.Keywords, ", "), p.Specificity, p.Boost, p.Support)
		}
	}
}

// ============================================================================
// FUNÇÕES UTILITÁRIAS
// ============================================================================

/*
 * Função: countTotalPatterns
 * Descrição: Conta o número total de padrões em toda a taxonomia
 * Objetivo: Calcular estatística agregada
 * Como faz: Soma o tamanho de todas as listas de padrões
 * Input: taxonomy (*PatternTaxonomy) - Taxonomia completa
 * Output: int - Total de padrões
 * Por que faz: Estatística útil para o sumário.
 */
func countTotalPatterns(taxonomy *PatternTaxonomy) int {
	total := 0
	for _, patterns := range taxonomy.Patterns {
		total += len(patterns)
	}
	return total
}

/*
 * Função: saveJSON
 * Descrição: Serializa e salva dados em formato JSON formatado
 * Objetivo: Persistir a taxonomia em disco
 * Como faz: 1. Serializa para JSON com indentação de 2 espaços
 *           2. Escreve no arquivo com permissões 0644
 * Input: path (string) - Caminho do arquivo
 *        data (interface{}) - Dados a serializar
 * Output: error - nil se bem-sucedido, erro caso contrário
 * Por que faz: A taxonomia precisa ser salva para uso pelos classificadores.
 */
func saveJSON(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, jsonData, 0644)
}

/*
 * Função: min
 * Descrição: Retorna o menor de dois inteiros
 * Objetivo: Função auxiliar para limitar iterações
 * Como faz: Comparação simples
 * Input: a, b (int) - Dois inteiros
 * Output: int - O menor valor
 * Por que faz: Go não tem função min builtin para inteiros.
 */
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
