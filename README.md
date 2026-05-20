# 🔍 IaC Scanner with AI

> **Terraform Security & Best Practices Analyzer**  
> Static rules + AI deep analysis for AWS and Azure infrastructure code.

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-App-red)](https://streamlit.io)
[![Claude AI](https://img.shields.io/badge/Claude-AI_Powered-orange)](https://anthropic.com)

---

## 🎯 What this project does

Analyzes Terraform (.tf) code and detects:

| Category | Examples |
|----------|---------|
| 🔴 Security | Public S3, hardcoded secrets, open security groups |
| 🟠 Compliance | Missing encryption, no deletion protection |
| 🟡 Best Practices | Missing tags, no versioning |
| 🤖 AI Analysis | Architecture anti-patterns, cost optimization |

---

## 🚀 Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

---

## 🏗️ Architecture

```
Terraform Code Input
       │
       ├── Static Rules Engine  (pattern matching — instant)
       │   └── 10 built-in rules (AWS + Azure)
       │
       └── AI Deep Analysis     (Claude API — contextual)
           └── Architecture, compliance, cost, security
               │
               ▼
       Security Score (0-100) + Prioritized Findings + Fix Suggestions
```

---

## 👤 Author

**Claudio Pereira Marcelino** — Senior Data Engineer | DevOps & AI  
[LinkedIn](https://linkedin.com/in/claudio-marcelino-a0006324) · [GitHub](https://github.com/claudioMjedi1979)
