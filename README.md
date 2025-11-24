# Pipeline de Análise de CWE/CVE - Guia Completo

Este documento fornece um guia completo para a pipeline de análise de CWE/CVE, um conjunto de programas em Go projetados para coletar, processar e analisar dados de vulnerabilidades de múltiplas bases de conhecimento de segurança. O sistema combina dados do MITRE (CWE, CAPEC, ATT&CK) com o National Vulnerability Database (NVD) para criar uma pipeline sofisticada de machine learning para classificação de vulnerabilidades e análise de ameaças.

---

## Visão Geral do Sistema

A pipeline consiste em **11 componentes interconectados** que trabalham juntos para transformar dados brutos de vulnerabilidades em inteligência acionável. O sistema foi projetado para ser executado em uma sequência específica, com cada componente se baseando nos resultados das etapas anteriores.

A pipeline atende a três propósitos principais:

1.  **Coleta e Preparação de Dados**: Baixar e estruturar bases de conhecimento de segurança de fontes autoritativas.
2.  **Treinamento de Machine Learning**: Construir modelos probabilísticos e baseados em padrões para classificação de vulnerabilidades.
3.  **Análise em Tempo de Execução**: Classificar novas vulnerabilidades e mapeá-las para padrões de ataque e técnicas.

---

## Fluxo de Trabalho Visual (Workflow)

![Fluxo de Trabalho da Pipeline de Análise de CWE/CVE](pipeline_workflow.png)

O diagrama acima ilustra o fluxo de dados completo através da pipeline, desde a configuração inicial até a classificação em tempo de execução e a manutenção.

---

## Sequência de Uso

### Fase 0: Configuração Inicial (Executar uma vez ou ao atualizar as bases de conhecimento)

Esta fase baixa e processa todas as bases de conhecimento de segurança necessárias. Execute estes componentes inicialmente para configurar o ambiente, ou periodicamente (ex: mensalmente) para atualizar os bancos de dados principais.

#### 1. **feeds-updater**

**O que faz**: Baixa e processa os dados mais recentes de CWE, CAPEC e MITRE ATT&CK de fontes oficiais.

**Por que é importante**: Esta é a base de toda a pipeline. Ele cria datasets estáveis e agnósticos de versão a partir de fontes autoritativas das quais todos os outros componentes dependem. Sem esta etapa, o sistema não tem base de conhecimento para trabalhar.

**Como funciona**: O programa executa quatro estágios principais em sequência. Primeiro, ele baixa o arquivo XML mais recente do CWE do MITRE, o extrai, analisa a estrutura XML e constrói um banco de dados JSON abrangente que inclui descrições de fraquezas, relações pai-filho e links para padrões de ataque CAPEC. Ele também constrói um arquivo `cwe_hierarchy.json` especializado que mapeia cada CWE aos seus vetores de ataque associados usando um mapeamento predefinido de mais de 260 relações CWE-para-vetor.

Segundo, ele baixa e processa o arquivo XML do CAPEC, extraindo informações detalhadas sobre cada padrão de ataque, incluindo fluxos de execução, pré-requisitos, habilidades necessárias, consequências e relações com CWEs e técnicas ATT&CK.

Terceiro, ele baixa os pacotes JSON STIX 2.1 para todos os três domínios do MITRE ATT&CK (Enterprise, Mobile e ICS) do repositório oficial do GitHub. Ele processa milhares de objetos STIX, incluindo técnicas, sub-técnicas, grupos de atores de ameaças, malware/ferramentas e mitigações, juntamente com todas as relações entre eles.

Finalmente, ele constrói um arquivo `relationships_db.json` abrangente que fornece mapeamentos bidirecionais entre os três frameworks (CWE ↔ CAPEC ↔ ATT&CK), permitindo consultas e análises poderosas entre frameworks.

**Entradas (Inputs)**:
- URLs externas (nenhum arquivo local necessário)
  - `http://cwe.mitre.org/data/xml/cwec_latest.xml.zip`
  - `https://capec.mitre.org/data/archive/capec_latest.zip`
  - `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/*/` (Enterprise, Mobile, ICS)

**Saídas (Outputs)**:
- `resources/cwe_db.json` - Banco de dados completo do CWE com descrições e relações
- `resources/cwe_hierarchy.json` - Hierarquia do CWE com mapeamentos de vetores de ataque (mais de 260 CWEs mapeados para 35 vetores de ataque)
- `resources/capec_db.json` - Banco de dados de padrões de ataque CAPEC
- `resources/attack_techniques_db.json` - Técnicas ATT&CK de todos os domínios
- `resources/attack_groups_db.json` - Grupos de atores de ameaças e seus TTPs
- `resources/attack_software_db.json` - Banco de dados de malware e ferramentas
- `resources/attack_mitigations_db.json` - Estratégias de mitigação
- `resources/relationships_db.json` - Mapeamentos de relacionamento entre frameworks
- `resources/metadata.json` - Timestamp da atualização e informações de versão

**Uso**:
```bash
./feeds-updater
```

**Principais Características**:
- Usa URLs estáveis e agnósticas de versão que não quebram quando novas versões são lançadas
- Processa todos os três domínios ATT&CK (Enterprise, Mobile, ICS) em um dataset unificado
- Cria mapeamentos de relacionamento bidirecionais para consultas eficientes
- Inclui 35 vetores de ataque predefinidos em 3 níveis de prioridade (Crítico, Alto, Médio)

---

#### 2. **cwe-hierarchy-builder** (Opcional/Autônomo)

**O que faz**: Constrói a estrutura hierárquica do CWE a partir dos dados XML oficiais do CWE.

**Por que é importante**: Embora essa funcionalidade esteja integrada no `feeds-updater`, esta versão autônoma pode ser útil para testes ou quando você precisa apenas reconstruir a hierarquia sem baixar todos os outros dados.

**Como funciona**: Ele baixa o arquivo XML do CWE, analisa as relações pai-filho definidas pela natureza "ChildOf" na seção `RelatedWeaknesses` e constrói uma estrutura de árvore que representa a taxonomia do CWE. Isso permite que o classificador entenda que, por exemplo, CWE-89 (SQL Injection) é um filho de CWE-74 (Injection).

**Entradas (Inputs)**:
- XML do CWE do MITRE (baixado automaticamente)

**Saídas (Outputs)**:
- `resources/cwe_hierarchy.json` - Estrutura hierárquica do CWE com relações pai-filho

**Uso**:
```bash
./cwe-hierarchy-builder
```

---

### Fase 1: Coleta de Dados de Treinamento (Executar Periodicamente)

Esta fase coleta dados de CVEs do mundo real do NVD para criar um dataset de treinamento rotulado. Execute esta fase mensalmente ou trimestralmente para manter os dados de treinamento atualizados.

#### 3. **phase1-collector**

**O que faz**: Baixa dados de CVE do National Vulnerability Database (NVD) e os transforma em um dataset de treinamento estruturado.

**Por que é importante**: Este componente preenche a lacuna entre as bases de conhecimento teóricas (CWE, CAPEC) и as vulnerabilidades do mundo real. Ele cria os exemplos rotulados necessários para treinar os modelos de machine learning, mapeando descrições reais de CVEs para seus CWEs e vetores de ataque associados.

**Como funciona**: O programa baixa o feed JSON do NVD para um ano específico (padrão: 2024), que contém milhares de registros de CVE. Para cada CVE, ele extrai a descrição em inglês e os IDs de CWE associados. Em seguida, usa uma tabela de mapeamento predefinida para converter cada CWE em um ou mais vetores de ataque. Por exemplo, se um CVE é marcado com CWE-89, ele é mapeado para o vetor de ataque "sql_injection". O programa lida com classificação multi-rótulo, pois um único CVE pode estar associado a múltiplos CWEs e, portanto, a múltiplos vetores de ataque.

A correspondência de vetores de ataque é organizada em três níveis de prioridade. O Nível 1 (Crítico) inclui 10 vetores de alto impacto como XSS, SQL injection, RCE e command injection. O Nível 2 (Prioridade Alta) inclui 10 vetores como CSRF, XXE e buffer overflow. O Nível 3 (Prioridade Média) inclui 15 vetores como DoS, open redirect e race conditions. Esta abordagem em camadas garante que os tipos de ataque mais perigosos estejam bem representados nos dados de treinamento.

**Entradas (Inputs)**:
- Feeds JSON do NVD (baixados automaticamente)
  - Padrão: `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz`
  - Recorre ao formato 1.1 se o 2.0 não estiver disponível

**Saídas (Outputs)**:
- `resources/training_data.json` - Dataset de treinamento estruturado com ID do CVE, descrição, CWEs, vetores de ataque e data de publicação

**Uso**:
```bash
./phase1-collector
```

**Configuração** (editar código-fonte):
- `year := 2024` - Mude para coletar dados de anos diferentes
- `outputFile := "resources/training_data.json"` - Caminho de saída

**Categorias de Vetores de Ataque** (35 no total):
- **Nível 1 (Crítico)**: xss, sql_injection, rce, command_injection, path_traversal, ssrf, deserialization, auth_bypass, authz_bypass, file_upload
- **Nível 2 (Alto)**: csrf, xxe, ldap_injection, jndi_injection, privilege_escalation, buffer_overflow, idor, http_desync, hardcoded_credentials, info_disclosure
- **Nível 3 (Médio)**: dos, nosql_injection, xpath_injection, open_redirect, session_fixation, crypto_failure, integer_overflow, use_after_free, null_pointer, format_string, email_injection, race_condition, ssti, input_validation, code_injection

**Formato de Saída**:
```json
[
  {
    "cve_id": "CVE-2024-12345",
    "description": "Uma vulnerabilidade de injeção de SQL em...",
    "cwes": ["89", "20"],
    "attack_vectors": ["sql_injection", "input_validation"],
    "published_date": "2024-01-15T10:30:00.000"
  }
]
```

---

### Fase 2: Treinamento de Modelos e Análise de Padrões (Executar após a Coleta de Dados)

Esta fase usa os dados de treinamento coletados para construir os modelos de classificação e os bancos de dados de padrões. Execute-os após coletar novos dados de treinamento.

#### 4. **phase2-trainer**

**O que faz**: Treina um classificador Naive Bayes para prever vetores de ataque a partir de descrições de CVEs.

**Por que é importante**: Este é o núcleo do motor de classificação de texto. O modelo Naive Bayes aprende as relações probabilísticas entre palavras em descrições de vulnerabilidades e categorias de vetores de ataque, permitindo que o sistema classifique novas vulnerabilidades com base puramente em suas descrições textuais.

**Como funciona**: O treinador implementa um classificador Naive Bayes multinomial com suavização de Laplace. Primeiro, ele tokeniza todas as descrições de CVE usando uma pipeline de pré-processamento sofisticada que converte o texto para minúsculas, remove números de versão (ex: "2.15.0"), retira IDs de CVE e filtra stopwords e palavras curtas. A lista de stopwords inclui não apenas palavras comuns em inglês, mas também termos genéricos específicos de segurança como "vulnerability", "attacker" e "allows" que têm baixo poder discriminativo.

Após a tokenização, ele constrói um vocabulário de todos os termos únicos em todo o conjunto de treinamento. Para cada vetor de ataque, ele calcula duas probabilidades chave. Primeiro, a probabilidade a priori P(vetor) representa quão comum cada vetor de ataque é nos dados de treinamento. Segundo, a verossimilhança P(palavra|vetor) representa quão provável é que cada palavra apareça em descrições daquele vetor de ataque. Essas verossimilhanças são calculadas usando a suavização de Laplace: (contagem_palavra + 1) / (total_palavras + tamanho_vocabulário), o que evita probabilidades zero para palavras não vistas.

O modelo também identifica as principais palavras discriminativas para cada vetor de ataque, o que fornece insights valiosos sobre quais termos são mais característicos de cada tipo de ataque. Por exemplo, as principais palavras para "sql_injection" podem incluir "query", "database", "select" e "union".

**Entradas (Inputs)**:
- `resources/training_data.json` (do phase1-collector)

**Saídas (Outputs)**:
- `resources/naive_bayes_model.json` - Modelo treinado com probabilidades e vocabulário

**Uso**:
```bash
./phase2-trainer
```

**Componentes do Modelo**:
- **Vocabulário**: Todas as palavras únicas (tipicamente 5.000-15.000 termos)
- **Probabilidades a Priori**: P(vetor) para cada vetor de ataque
- **Verossimilhanças**: P(palavra|vetor) para cada par palavra-vetor
- **Contagem de Palavras**: Dados de frequência brutos para análise
- **Principais Palavras**: Termos mais discriminativos por vetor (para depuração/análise)

**Filtragem de Stopwords**: Remove mais de 100 termos comuns e genéricos de segurança para melhorar a precisão da classificação.

**Formato de Saída**:
```json
{
  "attack_vectors": ["xss", "sql_injection", "rce", ...],
  "vector_priors": {
    "xss": 0.0823,
    "sql_injection": 0.0654,
    ...
  },
  "word_given_vector": {
    "xss": {
      "script": 0.00234,
      "javascript": 0.00189,
      ...
    }
  },
  "vocabulary": ["script", "query", "execute", ...],
  "total_documents": 12543
}
```

---

#### 5. **generate-pattern-taxonomy**

**O que faz**: Analisa os dados de treinamento para identificar padrões de palavras-chave de alta confiança para cada vetor de ataque.

**Por que é importante**: Enquanto o modelo Naive Bayes fornece classificação probabilística, a correspondência de padrões oferece uma abordagem complementar que é rápida, interpretável e altamente precisa para CVEs que contêm termos técnicos específicos e inequívocos. Essa abordagem híbrida melhora significativamente a precisão geral da classificação.

**Como funciona**: O programa usa a análise TF-IDF (Term Frequency-Inverse Document Frequency) para identificar termos que são frequentes dentro de um vetor de ataque específico e raros em outros vetores. Para cada vetor de ataque, ele agrupa todas as descrições de CVE que pertencem àquela categoria e calcula as frequências dos termos. Em seguida, calcula a pontuação IDF para cada termo, que mede quão específico esse termo é para o vetor.

A pontuação de especificidade é calculada como a razão da frequência do termo no vetor alvo para sua frequência em todos os vetores. Termos com alta especificidade (>0.6) e suporte suficiente (aparecendo em pelo menos 3 CVEs) são selecionados como palavras-chave de padrão. A cada padrão é atribuída uma pontuação de `boost` que reflete seu poder discriminativo, que é usada durante a classificação para aumentar a confiança quando esses padrões são detectados.

O sistema também inclui padrões críticos curados manualmente para vetores de ataque de alta prioridade para garantir que indicadores de vulnerabilidade bem conhecidos (como "JNDI" para injeção JNDI ou "union select" para injeção de SQL) sejam sempre reconhecidos.

**Entradas (Inputs)**:
- `resources/training_data.json` (do phase1-collector)

**Saídas (Outputs)**:
- `resources/pattern_taxonomy.json` - Regras de padrão com palavras-chave, pontuações de especificidade e valores de `boost`

**Uso**:
```bash
./generate-pattern-taxonomy
```

**Configuração** (constantes no código):
- `MinTermFrequency = 3` - Mínimo de vezes que um termo deve aparecer
- `MinSpecificity = 0.6` - Limiar mínimo de especificidade (60%)
- `MaxPatternsPerVector = 15` - Máximo de padrões a manter por vetor
- `MinPatternLength = 3` - Comprimento mínimo da palavra-chave

**Pontuação de Padrões**:
- **TF-IDF**: Identifica termos importantes
- **Especificidade**: Mede quão único um termo é para um vetor (escala 0-1)
- **Boost**: Multiplicador aplicado durante a classificação (tipicamente 1.2-2.0)
- **Suporte**: Número de CVEs contendo o padrão

**Formato de Saída**:
```json
{
  "patterns": {
    "sql_injection": [
      {
        "keywords": ["query", "database", "sql"],
        "specificity": 0.87,
        "boost": 1.8,
        "support": 234
      }
    ]
  },
  "stats": {
    "total_vectors": 35,
    "total_patterns": 412,
    "vector_counts": {...}
  }
}
```

---

#### 6. **cwe-frequency-analyzer**

**O que faz**: Analisa a distribuição e frequência de CWEs dentro dos dados de treinamento.

**Por que é importante**: Entender quais CWEs são mais comuns para cada vetor de ataque ajuda a priorizar a análise e fornece insights sobre a prevalência no mundo real de diferentes tipos de fraquezas. Esses dados são usados pelo mapeador de vetores para criar tabelas de consulta otimizadas.

**Como funciona**: O programa carrega os dados de treinamento e itera por todos os registros de CVE, contando quantas vezes cada CWE aparece para cada vetor de ataque. Ele calcula tanto as frequências absolutas (contagens brutas) quanto as frequências relativas (percentagens). Ele também identifica os principais N CWEs para cada vetor, que representam as fraquezas mais comuns associadas àquele tipo de ataque.

**Entradas (Inputs)**:
- `resources/training_data.json` (do phase1-collector)

**Saídas (Outputs)**:
- Saída no console com estatísticas de frequência
- Opcional: `resources/cwe_frequency_map.json` (se o salvamento for implementado)

**Uso**:
```bash
./cwe-frequency-analyzer
```

**Análise Fornecida**:
- Ocorrências totais de CWE por vetor de ataque
- Principais CWEs para cada vetor (classificados por frequência)
- Estatísticas de distribuição
- Análise de cobertura (qual percentagem de CVEs tem tags de CWE)

---

#### 7. **cwe-vector-mapper**

**O que faz**: Cria um mapeamento simplificado e baseado em frequência de CWEs para vetores de ataque.

**Por que é importante**: Isso fornece uma tabela de consulta rápida que pode ser usada para tradução rápida de CWE para vetor sem executar toda a pipeline de classificação. É particularmente útil para casos onde você já tem os IDs de CWE e só precisa saber os vetores de ataque associados.

**Como funciona**: Usando os dados de análise de frequência, ele cria um mapeamento limpo onde cada CWE é associado aos seus vetores de ataque mais comuns, classificados por frequência. Este mapeamento é otimizado para velocidade e pode ser usado como um método de classificação de fallback ou primário quando os IDs de CWE já são conhecidos.

**Entradas (Inputs)**:
- `resources/cwe_frequency_map.json` (do cwe-frequency-analyzer)

**Saídas (Outputs)**:
- `resources/cwe_vector_simplified.json` - Mapeamento simplificado de CWE para vetor

**Uso**:
```bash
./cwe-vector-mapper
```

**Formato de Saída**:
```json
{
  "89": ["sql_injection"],
  "79": ["xss"],
  "94": ["rce", "code_injection"],
  "502": ["deserialization", "rce"]
}
```

---

### Fase 3: Classificação em Tempo de Execução (Uso Operacional)

Esta é a fase operacional onde você classifica vulnerabilidades individuais em tempo real.

#### 8. **phase3-classifier**

**O que faz**: Classifica um CVE (por ID ou descrição) em vetores de ataque e o mapeia para padrões de ataque CAPEC relevantes.

**Por que é importante**: Esta é a principal ferramenta operacional para analistas de vulnerabilidades. Ela recebe um identificador ou descrição de CVE e produz uma lista classificada de vetores de ataque com pontuações de confiança, juntamente com padrões CAPEC relevantes que descrevem como a vulnerabilidade pode ser explorada.

**Como funciona**: O classificador usa uma abordagem híbrida sofisticada que combina três métodos de classificação. Primeiro, se os IDs de CWE estiverem disponíveis (seja da API do NVD ou fornecidos via linha de comando), ele realiza uma consulta na hierarquia do CWE, percorrendo a árvore do CWE para encontrar todos os vetores de ataque associados, incluindo aqueles herdados de fraquezas-pai.

Segundo, ele executa a classificação Naive Bayes na descrição do CVE. Ele tokeniza o texto, calcula a probabilidade posterior para cada vetor de ataque usando o teorema de Bayes (P(vetor|descrição) ∝ P(vetor) × ∏P(palavra|vetor)) e classifica os vetores por probabilidade.

Terceiro, ele aplica a correspondência de padrões usando a taxonomia de padrões. Ele varre a descrição em busca de palavras-chave de alta confiança e aplica pontuações de `boost` quando encontra correspondências.

Os resultados de todos os três métodos são então combinados usando um sistema de pontuação ponderada. A saída final é uma lista classificada de vetores de ataque com níveis de confiança (Alto, Médio, Baixo) com base nas pontuações de probabilidade.

Após identificar os vetores de ataque, o classificador os mapeia para padrões CAPEC usando o banco de dados de relacionamentos. Ele classifica os CAPECs por relevância usando uma função de pontuação que considera a força da relação CWE-CAPEC, a frequência do CWE nos dados de treinamento e a sobreposição de palavras-chave entre a descrição do CVE e a descrição do CAPEC.

**Entradas (Inputs)**:
- ID do CVE (buscado da API do NVD) OU texto da descrição + IDs de CWE opcionais
- `resources/cwe_hierarchy.json`
- `resources/naive_bayes_model.json`
- `resources/pattern_taxonomy.json` (opcional)
- `resources/cwe_frequency_map.json` (opcional)
- `resources/capec_db.json`
- `resources/relationships_db.json`

**Saídas (Outputs)**:
- Saída JSON para stdout com vetores de ataque e CAPECs classificados
- Processo de classificação detalhado (se o modo verboso estiver ativado)

**Uso**:
```bash
# Classificar por ID de CVE (busca no NVD)
./phase3-classifier -cve CVE-2021-44228

# Classificar por descrição com CWEs conhecidos
./phase3-classifier -d "permite que atacantes remotos executem código arbitrário via JNDI" -c "502,917"

# Mostrar processo detalhado
./phase3-classifier -cve CVE-2021-44228 -verbose

# Limitar aos 5 principais resultados
./phase3-classifier -cve CVE-2021-44228 -top 5
```

**Flags de Linha de Comando**:
- `-cve`: ID do CVE para buscar e classificar
- `-description` ou `-d`: Texto da descrição do CVE
- `-cwes` ou `-c`: IDs de CWE separados por vírgula
- `-top`: Número de resultados principais a retornar (padrão: 3)
- `-verbose` ou `-v`: Mostrar processo de classificação detalhado

**Métodos de Classificação**:
1.  **Consulta na Hierarquia do CWE**: Mapeamento direto de CWEs conhecidos
2.  **Naive Bayes**: Classificação de texto probabilística
3.  **Correspondência de Padrões**: Detecção baseada em palavras-chave com pontuações de `boost`

**Níveis de Confiança**:
- **Alto**: Probabilidade > 0.7 ou forte correspondência de padrão
- **Médio**: Probabilidade 0.4-0.7
- **Baixo**: Probabilidade < 0.4

**Formato de Saída**:
```json
{
  "cve_id": "CVE-2021-44228",
  "description": "Apache Log4j2 permite execução remota de código...",
  "cwes": ["502", "917"],
  "attack_vectors": [
    {
      "vector": "jndi_injection",
      "name": "JNDI Injection",
      "probability": 0.94,
      "confidence": "High",
      "source": "hybrid",
      "layer_contributions": ["cwe_hierarchy", "naive_bayes", "patterns"]
    },
    {
      "vector": "rce",
      "name": "Remote Code Execution",
      "probability": 0.89,
      "confidence": "High",
      "source": "hybrid"
    }
  ],
  "capecs": [
    {
      "capec_id": "253",
      "name": "JNDI Injection",
      "probability": 0.91,
      "confidence": "High"
    }
  ]
}
```

---

#### 9. **phase4-relationship**

**O que faz**: Estende a classificação da fase 3 mapeando os resultados para o framework MITRE ATT&CK, fornecendo uma análise completa da cadeia de ataque.

**Por que é importante**: Enquanto o CWE descreve a fraqueza e o CAPEC descreve o padrão de ataque, o ATT&CK descreve as táticas e técnicas do adversário. Este componente completa o quadro mostrando como uma vulnerabilidade se encaixa no contexto mais amplo de uma campanha de ataque, o que é essencial para modelagem de ameaças e planejamento de defesa.

**Como funciona**: Ele executa todos os mesmos passos de classificação do `phase3-classifier`, mas adiciona uma camada de mapeamento adicional. Após identificar os padrões CAPEC relevantes, ele usa o banco de dados de relacionamentos para encontrar todas as técnicas ATT&CK que estão associadas a esses CAPECs. Em seguida, enriquece a saída com informações detalhadas sobre cada técnica, incluindo suas táticas (ex: Acesso Inicial, Execução, Persistência), plataformas (ex: Windows, Linux, Nuvem) e links para o site do ATT&CK.

O classificador também implementa uma filtragem inteligente de *gap* de confiança. Em vez de sempre mostrar um número fixo de resultados, ele analisa a distribuição de probabilidade e filtra os resultados com base no *gap* de confiança. Se houver um vencedor claro (>90% de probabilidade), ele só mostra resultados adicionais se estiverem dentro de 20% da pontuação máxima. Para cenários de confiança média (60-90%), ele mostra os 3 primeiros ou até que o *gap* exceda 30%.

**Entradas (Inputs)**:
- O mesmo que o `phase3-classifier`, mais:
- `resources/attack_techniques_db.json`

**Saídas (Outputs)**:
- Saída JSON com vetores de ataque, CAPECs e técnicas ATT&CK
- Cadeia de ataque completa: CVE → CWE → Vetor de Ataque → CAPEC → Técnica ATT&CK

**Uso**:
```bash
# Mesma sintaxe do phase3-classifier
./phase4-relationship -cve CVE-2021-44228
./phase4-relationship -d "descrição" -c "94,502" -verbose
```

**Flags de Linha de Comando**: As mesmas do `phase3-classifier`

**Filtragem de Gap de Confiança**:
- **Confiança Alta (>90%)**: Mostra o resultado principal + qualquer um dentro de um *gap* de 20%
- **Confiança Média (60-90%)**: Mostra os 3 primeiros ou até um *gap* de 30%
- **Distribuída (<60%)**: Mostra todos os resultados

**Formato de Saída**:
```json
{
  "cve_id": "CVE-2021-44228",
  "attack_vectors": [...],
  "capecs": [...],
  "attack_techniques": [
    {
      "technique_id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactics": ["Initial Access"],
      "platforms": ["Linux", "Windows", "macOS"],
      "url": "https://attack.mitre.org/techniques/T1190/"
    },
    {
      "technique_id": "T1059",
      "name": "Command and Scripting Interpreter",
      "tactics": ["Execution"],
      "platforms": ["Linux", "Windows", "macOS"],
      "url": "https://attack.mitre.org/techniques/T1059/"
    }
  ]
}
```

---

### Manutenção e Uso Avançado (Conforme Necessário)

Estas ferramentas especializadas ajudam a melhorar a pipeline e permitem a exportação de dados para aplicações de machine learning externas.

#### 10. **batch-vector-reclassify**

**O que faz**: Re-executa a lógica de classificação mais recente sobre todo o dataset de treinamento para identificar e corrigir classificações incorretas.

**Por que é importante**: À medida que os modelos de classificação melhoram com o tempo (através de novos padrões, melhores algoritmos ou bases de conhecimento expandidas), os rótulos originais dos dados de treinamento podem se tornar desatualizados ou incorretos. Esta ferramenta ajuda a manter a qualidade dos dados, encontrando discrepâncias entre os rótulos originais e o que os modelos atuais preveriam.

**Como funciona**: Ele carrega os dados de treinamento existentes e, em seguida, reclassifica cada CVE usando a abordagem de classificação híbrida atual (hierarquia CWE + Naive Bayes + padrões). Para cada CVE, ele compara os rótulos de vetor de ataque originais com os recém-previstos. Ele sinaliza quaisquer discrepâncias e gera estatísticas detalhadas mostrando quantas classificações mudaram, quais vetores foram adicionados ou removidos e os níveis de confiança das novas previsões.

A ferramenta pode gerar um relatório de alterações sugeridas (para revisão manual) ou atualizar automaticamente o arquivo de dados de treinamento com as novas classificações. Isso cria um ciclo de feedback que melhora continuamente a qualidade dos dados de treinamento.

**Entradas (Inputs)**:
- `resources/training_data.json`
- Todos os arquivos de modelo (cwe_hierarchy.json, naive_bayes_model.json, pattern_taxonomy.json)

**Saídas (Outputs)**:
- `resources/training_data.json` atualizado (com rótulos melhorados)
- Relatório de estatísticas mostrando as alterações de classificação

**Uso**:
```bash
./batch-vector-reclassify
```

**Análise Fornecida**:
- Total de CVEs processados
- Número de classificações alteradas
- Vetores de ataque adicionados/removidos
- Distribuição de confiança das alterações
- Diff detalhado para cada CVE alterado

**Casos de Uso**:
- Garantia de qualidade para dados de treinamento
- Identificação de erros sistemáticos de rotulagem
- Melhoria da precisão do modelo através de refinamento iterativo
- Validação de novos algoritmos de classificação

---

#### 11. **generate-embeddings-dataset**

**O que faz**: Gera representações vetoriais numéricas (embeddings) de descrições de CVE e CAPEC e as exporta para um arquivo de dataset JSON.

**Por que é importante**: Esta é uma **utilidade de exportação de dados autônoma** que cria um dataset de embeddings para uso externo ou integração futura. **NÃO é atualmente usada pela pipeline de classificação** (fase3/fase4). Os embeddings podem ser usados para aplicações avançadas de machine learning fora desta pipeline, como busca semântica, análise de similaridade, clustering ou treinamento de modelos de deep learning.

**Como funciona**: O programa usa a API de Embeddings da OpenAI (modelo `text-embedding-3-small`) para converter descrições de CVE e de padrões de ataque CAPEC em vetores numéricos densos de 1536 dimensões. Ele processa tanto o banco de dados CAPEC quanto os dados de treinamento de CVE, gerando embeddings para cada descrição de texto.

O programa implementa um robusto rastreamento de progresso e processamento retomável, o que é crítico porque gerar embeddings para milhares de itens pode levar horas e custa dinheiro (a API da OpenAI cobra por token). Se o processo for interrompido, ele pode continuar de onde parou usando o arquivo de progresso. A saída é um arquivo JSON onde cada registro contém o ID (CVE-XXXX ou CAPEC-XXX), tipo, texto original, vetor de embedding e metadados.

**Entradas (Inputs)**:
- `resources/capec_db.json` (do feeds-updater)
- `resources/training_data.json` (do phase1-collector) OU baixa do NVD se não estiver disponível
- Variável de ambiente: `OPENAI_API_KEY` (obrigatória)

**Saídas (Outputs)**:
- `resources/embeddings_dataset.json` - Array JSON de registros de embedding
- `resources/embeddings_progress.json` - Rastreamento de progresso (pode ser deletado após a conclusão)

**Uso**:
```bash
# Defina sua chave de API da OpenAI primeiro
export OPENAI_API_KEY="sk-..."

# Gere os embeddings (retomável)
./generate-embeddings-dataset
```

**Notas Importantes**:
- **Requer chave de API da OpenAI** e incorrerá em custos de API
- Usa o modelo `text-embedding-3-small` (1536 dimensões)
- Processa ~20 itens por segundo (com limitação de taxa para evitar throttling da API)
- Pode levar várias horas para datasets grandes
- Retomável: se interrompido, re-execute para continuar do último checkpoint
- **Não integrado com os classificadores**: Esta é apenas uma ferramenta de exportação de dados

**Modelo de Embedding**:
- OpenAI `text-embedding-3-small`
- 1536 dimensões por vetor
- ~$0.02 por 1M de tokens (verifique os preços atuais da OpenAI)

**Casos de Uso** (Externos a esta pipeline):
- Busca de similaridade semântica em bancos de dados vetoriais (Pinecone, Weaviate, Qdrant)
- Treinamento de classificadores de deep learning personalizados (PyTorch, TensorFlow)
- Clustering e visualização (t-SNE, UMAP)
- Encontrar vulnerabilidades similares por distância vetorial
- Pesquisa e experimentação com abordagens neurais

**Formato de Saída**:
```json
[
  {
    "id": "CVE-2021-44228",
    "type": "CVE",
    "text": "Apache Log4j2 permite execução remota de código...",
    "embedding": [0.0234, -0.0156, 0.0891, ...],  // 1536 dimensões
    "metadata": {
      "published": "2021-12-10T10:00:00.000"
    }
  },
  {
    "id": "CAPEC-253",
    "type": "CAPEC",
    "text": "Injeção JNDI: Um atacante explora...",
    "embedding": [0.0189, -0.0234, 0.0756, ...],
    "metadata": {
      "name": "JNDI Injection",
      "severity": "High",
      "likelihood": "Medium"
    }
  }
]
```

---

## Resumo do Fluxo de Dados

A tabela a seguir resume as entradas e saídas de cada componente:

| Componente | Entradas Primárias | Saídas Primárias | Dependências |
|:---|:---|:---|:---|
| feeds-updater | URLs Externas (MITRE, GitHub) | resources/*.json (9 arquivos) | Nenhuma |
| cwe-hierarchy-builder | XML do CWE (baixado) | cwe_hierarchy.json | Nenhuma |
| phase1-collector | Feeds JSON do NVD | training_data.json | Nenhuma |
| phase2-trainer | training_data.json | naive_bayes_model.json | phase1-collector |
| generate-pattern-taxonomy | training_data.json | pattern_taxonomy.json | phase1-collector |
| cwe-frequency-analyzer | training_data.json | Saída no console / JSON | phase1-collector |
| cwe-vector-mapper | cwe_frequency_map.json | cwe_vector_simplified.json | cwe-frequency-analyzer |
| phase3-classifier | ID/descrição do CVE + todos os modelos | Resultados de classificação JSON | feeds-updater, phase2-trainer |
| phase4-relationship | ID/descrição do CVE + todos os modelos | JSON com mapeamento ATT&CK | feeds-updater, phase2-trainer |
| batch-vector-reclassify | training_data.json + todos os modelos | training_data.json atualizado | fase1, fase2 |
| generate-embeddings-dataset | training_data.json, capec_db.json, OPENAI_API_KEY | embeddings_dataset.json | phase1-collector, feeds-updater |

---

## Exemplo de Fluxo de Trabalho Completo

Aqui está um exemplo completo de como configurar e usar a pipeline do zero:

### Passo 1: Configuração Inicial
```bash
# Baixar e processar todas as bases de conhecimento
./feeds-updater
# Saída: resources/cwe_db.json, capec_db.json, attack_*.json, relationships_db.json, metadata.json
```

### Passo 2: Coletar Dados de Treinamento
```bash
# Coletar CVEs de 2024
./phase1-collector
# Saída: resources/training_data.json (com ~12.000-20.000 CVEs)
```

### Passo 3: Treinar Modelos
```bash
# Treinar classificador Naive Bayes
./phase2-trainer
# Saída: resources/naive_bayes_model.json

# Gerar taxonomia de padrões
./generate-pattern-taxonomy
# Saída: resources/pattern_taxonomy.json

# Analisar frequências de CWE
./cwe-frequency-analyzer
# Saída: Estatísticas no console

# Criar mapeamentos simplificados
./cwe-vector-mapper
# Saída: resources/cwe_vector_simplified.json
```

### Passo 4: Classificar Vulnerabilidades
```bash
# Classificar o Log4Shell
./phase3-classifier -cve CVE-2021-44228 -verbose

# Obter cadeia de ataque completa com ATT&CK
./phase4-relationship -cve CVE-2021-44228

# Classificar por descrição
./phase4-relationship -d "Injeção de SQL no formulário de login permite bypass de autenticação" -c "89,287"
```

### Passo 5: Manutenção (Opcional)
```bash
# Melhorar a qualidade dos dados de treinamento
./batch-vector-reclassify

# Gerar embeddings para uso externo (requer chave de API da OpenAI)
export OPENAI_API_KEY="sk-..."
./generate-embeddings-dataset
```

---

## Principais Melhorias em Relação a Versões Anteriores

A pipeline atual oferece várias vantagens significativas:

**Fontes de Dados Estáveis**: O sistema usa repositórios oficiais do GitHub e URLs agnósticas de versão para todas as fontes de dados, eliminando completamente o problema de links quebrados quando novas versões são lançadas.

**Modelo de Dados Abrangente**: A pipeline agora processa os dados completos do STIX 2.1 para o MITRE ATT&CK, incluindo técnicas, grupos, software e mitigações em todos os três domínios (Enterprise, Mobile, ICS).

**Mapeamento de Relacionamentos Rico**: O arquivo `relationships_db.json` fornece mapeamentos explícitos e bidirecionais entre CWE, CAPEC e ATT&CK, permitindo uma poderosa análise entre frameworks e reconstrução da cadeia de ataque.

**Classificação Híbrida**: A combinação de consulta na hierarquia do CWE, classificação probabilística Naive Bayes e correspondência de padrões fornece uma precisão superior em comparação com qualquer método único isoladamente.

**Filtragem Inteligente**: A filtragem de *gap* de confiança na fase 4 garante que os usuários vejam os resultados mais relevantes sem serem sobrecarregados por previsões de baixa confiança.

**Melhoria Iterativa**: A ferramenta de reclassificação em lote cria um ciclo de feedback que melhora continuamente a qualidade dos dados de treinamento ao longo do tempo.

**Capacidade de Exportação de Dados**: O gerador de embeddings fornece uma ponte para ferramentas externas de deep learning e bancos de dados vetoriais, permitindo análises avançadas além dos classificadores integrados.

---

## Referência de Arquivos de Recursos

| Arquivo | Tamanho (Aprox) | Descrição | Frequência de Atualização |
|:---|:---|:---|:---|
| cwe_db.json | 5-10 MB | Banco de dados completo do CWE | Mensal (quando o MITRE atualiza) |
| cwe_hierarchy.json | 1-2 MB | Árvore do CWE com vetores de ataque | Mensal |
| capec_db.json | 3-5 MB | Padrões de ataque CAPEC | Mensal |
| attack_techniques_db.json | 2-4 MB | Técnicas ATT&CK (todos os domínios) | Mensal |
| attack_groups_db.json | 500 KB | Grupos de atores de ameaças | Mensal |
| attack_software_db.json | 1 MB | Malware e ferramentas | Mensal |
| attack_mitigations_db.json | 500 KB | Estratégias de mitigação | Mensal |
| relationships_db.json | 1-2 MB | Mapeamentos entre frameworks | Mensal |
| metadata.json | 1 KB | Timestamps de atualização | Mensal |
| training_data.json | 10-50 MB | Dataset de treinamento de CVE | Trimestral |
| naive_bayes_model.json | 5-20 MB | Classificador treinado | Após atualização dos dados de treinamento |
| pattern_taxonomy.json | 500 KB | Regras de padrão | Após atualização dos dados de treinamento |
| cwe_frequency_map.json | 100 KB | Estatísticas de frequência de CWE | Após atualização dos dados de treinamento |
| cwe_vector_simplified.json | 50 KB | Mapeamentos simplificados de CWE | Após análise de frequência |
| embeddings_dataset.json | 50-200 MB | Embeddings para ML externo (opcional) | Sob demanda (requer chave de API da OpenAI) |
| embeddings_progress.json | 10 KB | Rastreamento de progresso para embeddings | Durante a geração de embeddings (pode deletar depois) |

---

## Solução de Problemas (Troubleshooting)

**Problema**: `feeds-updater` falha ao baixar dados do CWE ou CAPEC
**Solução**: Verifique sua conexão com a internet e verifique se as URLs do MITRE estão acessíveis. O programa mostrará códigos de erro HTTP específicos se o download falhar.

**Problema**: `phase1-collector` não retorna nenhum CVE
**Solução**: Verifique se a URL do feed do NVD está correta e se o ano é válido. Tente mudar o ano ou verifique se o NVD mudou o formato do feed.

**Problema**: `phase2-trainer` mostra "Error opening file"
**Solução**: Certifique-se de ter executado o `phase1-collector` primeiro para gerar o arquivo `training_data.json`.

**Problema**: `phase3-classifier` retorna "Error loading CWE hierarchy"
**Solução**: Execute o `feeds-updater` para gerar os arquivos de recursos necessários.

**Problema**: Os resultados da classificação parecem imprecisos
**Solução**: Verifique se seus dados de treinamento estão atuais e representativos. Execute o `batch-vector-reclassify` para melhorar a qualidade dos dados, ou colete CVEs mais recentes com o `phase1-collector`.

**Problema**: Limitação de taxa da API do NVD
**Solução**: A API do NVD tem limites de taxa. Se você estiver processando muitos CVEs, adicione atrasos entre as solicitações ou use as ferramentas de processamento em lote durante os horários de menor movimento.

**Problema**: `generate-embeddings-dataset` falha com "OPENAI_API_KEY environment variable not set"
**Solução**: Defina sua chave de API da OpenAI: `export OPENAI_API_KEY="sk-sua-chave-aqui"`. Você precisa de uma conta OpenAI ativa com acesso à API.

**Problema**: A geração de embeddings é muito lenta ou cara
**Solução**: O processo usa a API da OpenAI, que tem custos e limites de taxa. Considere processar apenas um subconjunto de dados ou use o arquivo de progresso para retomar sessões interrompidas. Verifique os preços da OpenAI e seus limites de uso.

---

## Melhores Práticas

**Atualize as Bases de Conhecimento Mensalmente**: Execute o `feeds-updater` pelo menos uma vez por mês para manter os dados de CWE, CAPEC e ATT&CK atualizados.

**Atualize os Dados de Treinamento Trimestralmente**: Colete novos CVEs com o `phase1-collector` a cada 3-4 meses para garantir que seus modelos reflitam as tendências atuais de vulnerabilidades.

**Retreine Após Atualizações de Dados**: Sempre execute o `phase2-trainer` e o `generate-pattern-taxonomy` após atualizar os dados de treinamento.

**Use o Modo Verboso para Análise**: Ao investigar vulnerabilidades específicas, use a flag `-verbose` para entender como a classificação foi determinada.

**Valide com Múltiplas Ferramentas**: Compare os resultados da fase 3 e 4 com a análise manual, especialmente para vulnerabilidades críticas.

**Mantenha a Qualidade dos Dados**: Periodicamente, execute o `batch-vector-reclassify` para identificar e corrigir erros de rotulagem nos dados de treinamento.

**Versione Seus Recursos**: Mantenha o diretório `resources/` sob controle de versão para rastrear as alterações nas bases de conhecimento ao longo do tempo.

**Monitore o Uso da API**: Se estiver usando APIs externas (para embeddings ou consultas ao NVD), monitore seu uso para evitar limites de taxa e custos inesperados.

---

## Conclusão

Esta pipeline de análise de CWE/CVE representa um sistema abrangente e pronto para produção para classificação de vulnerabilidades e análise de ameaças. Ao combinar bases de conhecimento autoritativas do MITRE com dados de vulnerabilidades do mundo real do NVD, e aplicando tanto machine learning tradicional quanto técnicas modernas de reconhecimento de padrões, o sistema fornece inteligência precisa и acionável para equipes de segurança.

O design modular permite que cada componente seja executado de forma independente ou como parte de um fluxo de trabalho automatizado, tornando-o adequado tanto para análises ad-hoc quanto para integração contínua em operações de segurança. Os ricos mapeamentos de relacionamento permitem consultas poderosas entre frameworks, suportando casos de uso desde a avaliação de vulnerabilidades até a modelagem de ameaças e a pesquisa de segurança.

---

**Autor**: Manus AI
**Última Atualização**: 2024
**Versão**: 2.0
