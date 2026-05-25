<div align="center">

# 🔍 IaC Scanner with AI

**Terraform Security & Best Practices Analyzer**  
*Analisador de Segurança Terraform com Inteligência Artificial*

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-App-red?logo=streamlit)](https://streamlit.io)
[![Claude AI](https://img.shields.io/badge/Claude-AI_Powered-orange)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 🇺🇸 English

### What this project does

Analyzes Terraform (`.tf`) code combining two engines:

- **Static Rules Engine** — 10 built-in rules for AWS and Azure (instant, no API needed)
- **AI Deep Analysis** — Claude AI detects architecture anti-patterns, compliance issues and cost problems that static rules miss

Returns a **Security Score (0–100)** with prioritized findings and specific fix suggestions for each problem found.

### Problems detected

| Category | Examples |
|----------|---------|
| 🔴 Critical | Public S3 buckets, hardcoded secrets, open security groups (0.0.0.0/0) |
| 🟠 High | RDS without encryption, no deletion protection, Azure KV without soft-delete |
| 🟡 Medium | Missing tags, large instance types without justification |
| 🟢 Low | Missing versioning, general best practices |
| 🤖 AI | Architecture anti-patterns, compliance (LGPD, SOC2, HIPAA), cost optimization |

### Architecture

```
Terraform Code Input (.tf)
         │
         ├──► Static Rules Engine   ── instant pattern matching
         │    10 rules (AWS + Azure)    no external API needed
         │
         └──► AI Deep Analysis      ── Claude API
              contextual understanding   architecture + compliance + cost
                        │
                        ▼
         Security Score (0–100)
         Prioritized Findings
         Fix Suggestions per issue
         Export JSON Report
```

### Quick Start

```bash
git clone https://github.com/claudioMjedi1979/iac-scanner-ai
cd iac-scanner-ai
pip install -r requirements.txt
streamlit run app.py
```

### Real-world context

This project was inspired by a real enterprise project where I built a complete CI/CD pipeline for Azure Databricks — 9 independent Terraform stacks, TFLint, Terrascan, Private Endpoints and Unity Catalog — for a large healthcare organization. The security checks in this scanner reflect real problems found and solved in production.

---

## 🇧🇷 Português

### O que esse projeto faz

Analisa código Terraform (`.tf`) combinando dois motores:

- **Engine de Regras Estáticas** — 10 regras para AWS e Azure (instantâneo, sem API)
- **Análise Profunda com IA** — Claude AI detecta anti-padrões de arquitetura, problemas de compliance e custo que as regras estáticas não capturam

Retorna um **Score de Segurança (0–100)** com findings priorizados e sugestões de correção específicas para cada problema encontrado.

### Problemas detectados

| Categoria | Exemplos |
|-----------|---------|
| 🔴 Crítico | Buckets S3 públicos, secrets hardcoded, security groups abertos (0.0.0.0/0) |
| 🟠 Alto | RDS sem criptografia, sem deletion protection, Azure KV sem soft-delete |
| 🟡 Médio | Tags faltando, instance types grandes sem justificativa |
| 🟢 Baixo | Versioning ausente, boas práticas gerais |
| 🤖 IA | Anti-padrões de arquitetura, compliance (LGPD, SOC2, HIPAA), otimização de custo |

### Arquitetura

```
Código Terraform (.tf)
         │
         ├──► Engine de Regras Estáticas  ── pattern matching instantâneo
         │    10 regras (AWS + Azure)         sem API externa necessária
         │
         └──► Análise Profunda com IA    ── Claude API
              entendimento contextual        arquitetura + compliance + custo
                        │
                        ▼
         Score de Segurança (0–100)
         Findings Priorizados
         Sugestões de Correção
         Exportação Relatório JSON
```

### Como rodar

```bash
git clone https://github.com/claudioMjedi1979/iac-scanner-ai
cd iac-scanner-ai
pip install -r requirements.txt
streamlit run app.py
```

### Contexto real

Este projeto foi inspirado em um projeto enterprise real onde construí uma esteira CI/CD completa para Azure Databricks — 9 stacks Terraform independentes, TFLint, Terrascan, Private Endpoints e Unity Catalog — para uma grande organização do setor de saúde. Os checks de segurança deste scanner refletem problemas reais encontrados e resolvidos em produção.

---

<div align="center">

**👤 Claudio Pereira Marcelino**  
Senior Data Engineer | DevOps & AI | 15+ anos  
[LinkedIn](https://linkedin.com/in/claudio-marcelino-a0006324) · [GitHub](https://github.com/claudioMjedi1979) · [AuditAI](https://auditai.streamlit.app)

</div>
