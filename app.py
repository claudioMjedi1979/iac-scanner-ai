"""
IaC Scanner with AI — Terraform Security & Best Practices Analyzer
Analisa codigo Terraform usando IA e regras de seguranca.
"""

import streamlit as st
import anthropic
import json
import re
from datetime import datetime
from pathlib import Path

st.set_page_config(
    page_title="IaC Scanner AI",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    [data-testid="stAppViewContainer"] { background-color: #0d1117; }
    .header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #30363d;
        border-left: 5px solid #f39c12;
        padding: 1.5rem 2rem; border-radius: 10px;
        margin-bottom: 1.5rem; color: white;
    }
    .finding {
        border-radius: 8px; padding: 1rem 1.2rem;
        margin: 0.5rem 0; color: #c9d1d9;
    }
    .critical { background: #2d0f0f; border-left: 5px solid #e74c3c; }
    .high     { background: #2d1a0f; border-left: 5px solid #e67e22; }
    .medium   { background: #2d2a0f; border-left: 5px solid #f1c40f; }
    .low      { background: #0f2d1a; border-left: 5px solid #2ecc71; }
    .info     { background: #0f1a2d; border-left: 5px solid #3498db; }
    .score-box {
        background: #161b22; border: 2px solid #30363d;
        border-radius: 12px; padding: 1.5rem;
        text-align: center; color: white;
    }
    .score-num { font-size: 3.5rem; font-weight: 900; }
    .score-red    { color: #e74c3c; }
    .score-orange { color: #e67e22; }
    .score-yellow { color: #f1c40f; }
    .score-green  { color: #2ecc71; }
    .badge {
        display: inline-block; padding: 0.2rem 0.7rem;
        border-radius: 20px; font-size: 0.78rem;
        font-weight: bold; margin: 2px;
    }
    .badge-critical { background: #e74c3c; color: white; }
    .badge-high     { background: #e67e22; color: white; }
    .badge-medium   { background: #f1c40f; color: black; }
    .badge-low      { background: #2ecc71; color: black; }
    .code-block {
        background: #161b22; border: 1px solid #30363d;
        border-radius: 8px; padding: 1rem;
        font-family: monospace; font-size: 0.85rem;
        color: #c9d1d9; white-space: pre-wrap;
    }
</style>
""", unsafe_allow_html=True)

# ── AI Client ─────────────────────────────────────────────────────────────────
@st.cache_resource
def get_client():
    return anthropic.Anthropic()

def call_ai(system: str, user: str, max_tokens: int = 2000) -> str:
    client = get_client()
    try:
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return resp.content[0].text
    except Exception as e:
        return f"ERROR: {str(e)}"

# ── Static Rules Engine ───────────────────────────────────────────────────────
STATIC_RULES = [
    {
        "id": "TF-SEC-001",
        "name": "Public S3 Bucket",
        "severity": "CRITICAL",
        "pattern": r'acl\s*=\s*"public-read"',
        "message": "S3 bucket with public-read ACL — data exposed to internet",
        "fix": 'acl = "private"',
        "resource": "aws_s3_bucket",
    },
    {
        "id": "TF-SEC-002",
        "name": "S3 Versioning Disabled",
        "severity": "MEDIUM",
        "pattern": r'aws_s3_bucket(?!.*versioning)',
        "message": "S3 bucket without versioning — no data recovery if deleted",
        "fix": 'Add versioning { enabled = true }',
        "resource": "aws_s3_bucket",
    },
    {
        "id": "TF-SEC-003",
        "name": "Security Group All Traffic",
        "severity": "CRITICAL",
        "pattern": r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
        "message": "Security group allows all inbound traffic from internet (0.0.0.0/0)",
        "fix": "Restrict to specific CIDR blocks or use security group references",
        "resource": "aws_security_group",
    },
    {
        "id": "TF-SEC-004",
        "name": "Hardcoded Secret",
        "severity": "CRITICAL",
        "pattern": r'(password|secret|token|key)\s*=\s*"[^"]{4,}"',
        "message": "Hardcoded secret detected in Terraform code — use variables or secrets manager",
        "fix": "Use var.password or AWS Secrets Manager reference",
        "resource": "any",
    },
    {
        "id": "TF-SEC-005",
        "name": "No Encryption at Rest",
        "severity": "HIGH",
        "pattern": r'aws_db_instance(?!.*storage_encrypted\s*=\s*true)',
        "message": "RDS instance without encryption at rest",
        "fix": 'Add storage_encrypted = true',
        "resource": "aws_db_instance",
    },
    {
        "id": "TF-COST-001",
        "name": "Large Instance Type",
        "severity": "MEDIUM",
        "pattern": r'instance_type\s*=\s*"(x1|p3|p4|r6g\.16|m6g\.16)',
        "message": "Very large instance type detected — review if necessary",
        "fix": "Consider smaller instance type or use Auto Scaling",
        "resource": "aws_instance",
    },
    {
        "id": "TF-BP-001",
        "name": "Missing Tags",
        "severity": "LOW",
        "pattern": r'resource "aws_\w+"[^}]+?(?!tags)',
        "message": "Resource without tags — makes cost tracking and governance difficult",
        "fix": 'Add tags = { Environment = var.env, Project = var.project_name }',
        "resource": "any",
    },
    {
        "id": "TF-BP-002",
        "name": "No Deletion Protection",
        "severity": "HIGH",
        "pattern": r'aws_db_instance(?!.*deletion_protection\s*=\s*true)',
        "message": "RDS instance without deletion protection — can be accidentally destroyed",
        "fix": 'Add deletion_protection = true',
        "resource": "aws_db_instance",
    },
    {
        "id": "TF-AZ-001",
        "name": "Public Network Access Enabled",
        "severity": "HIGH",
        "pattern": r'public_network_access_enabled\s*=\s*true',
        "message": "Azure resource with public network access enabled — prefer Private Endpoints",
        "fix": 'Set public_network_access_enabled = false and use Private Endpoints',
        "resource": "azurerm_*",
    },
    {
        "id": "TF-AZ-002",
        "name": "No Soft Delete on Key Vault",
        "severity": "HIGH",
        "pattern": r'azurerm_key_vault(?!.*soft_delete_retention_days)',
        "message": "Azure Key Vault without soft delete — keys permanently lost if deleted",
        "fix": 'Add soft_delete_retention_days = 90',
        "resource": "azurerm_key_vault",
    },
]

def run_static_scan(code: str) -> list:
    """Run static pattern-based rules on Terraform code."""
    findings = []
    for rule in STATIC_RULES:
        if re.search(rule["pattern"], code, re.IGNORECASE | re.DOTALL):
            findings.append({
                "rule_id":  rule["id"],
                "name":     rule["name"],
                "severity": rule["severity"],
                "message":  rule["message"],
                "fix":      rule["fix"],
                "source":   "static",
            })
    return findings

def severity_order(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(s, 5)

def calculate_score(findings: list) -> int:
    """Calculate security score 0-100 based on findings."""
    if not findings:
        return 100
    penalties = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
    total_penalty = sum(penalties.get(f["severity"], 0) for f in findings)
    return max(0, 100 - total_penalty)

def score_color(score: int) -> str:
    if score < 40: return "score-red"
    if score < 60: return "score-orange"
    if score < 80: return "score-yellow"
    return "score-green"

def score_label(score: int) -> str:
    if score < 40: return "CRITICAL RISK"
    if score < 60: return "HIGH RISK"
    if score < 80: return "NEEDS IMPROVEMENT"
    return "GOOD"

# ── Sample Terraform Files ─────────────────────────────────────────────────────
SAMPLE_BAD = '''# BAD EXAMPLE — Multiple security issues
resource "aws_s3_bucket" "data_lake" {
  bucket = "my-data-lake-bucket"
  acl    = "public-read"
}

resource "aws_db_instance" "main_db" {
  identifier        = "prod-database"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  username          = "admin"
  password          = "MySuperSecret123!"
  storage_encrypted = false
}

resource "aws_security_group" "web" {
  name = "allow-all"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "azurerm_key_vault" "kv" {
  name                = "my-keyvault"
  resource_group_name = var.rg_name
  location            = var.location
  sku_name            = "standard"
  public_network_access_enabled = true
}
'''

SAMPLE_GOOD = '''# GOOD EXAMPLE — Security best practices applied
resource "aws_s3_bucket" "data_lake" {
  bucket = "my-data-lake-bucket"
  tags = {
    Environment = var.env
    Project     = "medallion-pipeline"
    Owner       = "data-team"
  }
}

resource "aws_s3_bucket_acl" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_db_instance" "main_db" {
  identifier          = "prod-database"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  username            = var.db_username
  password            = var.db_password
  storage_encrypted   = true
  deletion_protection = true
  tags = {
    Environment = var.env
  }
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }
}

resource "azurerm_key_vault" "kv" {
  name                          = "my-keyvault"
  resource_group_name           = var.rg_name
  location                      = var.location
  sku_name                      = "standard"
  soft_delete_retention_days    = 90
  purge_protection_enabled      = true
  public_network_access_enabled = false
}
'''

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔍 IaC Scanner AI")
    st.caption("Terraform Security Analyzer")
    st.divider()

    st.markdown("### ⚙️ Configurações")
    cloud = st.selectbox("Cloud Provider", ["AWS", "Azure", "Both"])
    ai_analysis = st.toggle("Análise Profunda com IA", value=True)
    show_fixes  = st.toggle("Mostrar Correções", value=True)
    lang        = st.radio("Idioma da análise", ["Português", "English"], horizontal=True)

    st.divider()
    st.markdown("### 📊 Severidades")
    st.markdown("🔴 **CRITICAL** — Risco imediato")
    st.markdown("🟠 **HIGH** — Risco alto")
    st.markdown("🟡 **MEDIUM** — Risco moderado")
    st.markdown("🟢 **LOW** — Melhoria sugerida")
    st.markdown("🔵 **INFO** — Informativo")

    st.divider()
    st.caption("Built by Claudio Marcelino")
    st.caption("github.com/claudioMjedi1979")

# ── Main ───────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="header">
    <h2 style="margin:0">🔍 IaC Scanner with AI</h2>
    <p style="margin:0;opacity:0.8">
    Terraform Security & Best Practices Analyzer — Static Rules + AI Deep Analysis
    </p>
</div>
""", unsafe_allow_html=True)

# ── Input tabs ────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["📝 Colar código", "📁 Upload arquivo", "🧪 Exemplos"])

with tab1:
    terraform_code = st.text_area(
        "Cole seu código Terraform aqui",
        height=300,
        placeholder="# Cole seu código .tf aqui...\nresource \"aws_s3_bucket\" \"example\" {\n  ...\n}",
    )

with tab2:
    uploaded = st.file_uploader("Upload arquivo .tf", type=["tf"])
    terraform_code_file = uploaded.read().decode("utf-8") if uploaded else ""
    if terraform_code_file:
        st.code(terraform_code_file[:500] + "..." if len(terraform_code_file) > 500 else terraform_code_file,
                language="hcl")

with tab3:
    col1, col2 = st.columns(2)
    with col1:
        if st.button("❌ Exemplo com problemas", use_container_width=True):
            st.session_state["sample"] = SAMPLE_BAD
    with col2:
        if st.button("✅ Exemplo sem problemas", use_container_width=True):
            st.session_state["sample"] = SAMPLE_GOOD
    if "sample" in st.session_state:
        st.code(st.session_state["sample"], language="hcl")

# Resolve final code
final_code = (
    st.session_state.get("sample")
    or terraform_code_file
    or terraform_code
)

# ── Scan button ───────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns([2, 1, 2])
with col2:
    scan_btn = st.button("🚀 Escanear", type="primary", use_container_width=True,
                         disabled=not bool(final_code and final_code.strip()))

if scan_btn and final_code:
    with st.spinner("Rodando análise estática..."):
        static_findings = run_static_scan(final_code)
        static_findings.sort(key=lambda x: severity_order(x["severity"]))

    ai_findings = []
    if ai_analysis:
        lang_str = "em português brasileiro" if lang == "Português" else "in English"
        with st.spinner("Analisando com IA (análise profunda)..."):
            system = f"""You are an expert in Terraform security, DevOps best practices and cloud infrastructure.
You specialize in AWS and Azure security. Respond {lang_str}.
Be precise, technical and actionable. Focus on real security risks, not just style."""

            prompt = f"""Analyze this Terraform code for security issues, best practices and cost optimization.
Cloud focus: {cloud}

TERRAFORM CODE:
```hcl
{final_code}
```

Return a JSON array (and ONLY the JSON, no other text) with findings:
[
  {{
    "rule_id": "AI-001",
    "name": "Short finding name",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "message": "Clear explanation of the problem",
    "fix": "Specific fix with code example",
    "source": "ai"
  }}
]

Focus on:
1. Security vulnerabilities not caught by simple pattern matching
2. Architecture anti-patterns
3. Cost optimization opportunities
4. Compliance issues (LGPD, SOC2, HIPAA if applicable)
5. Missing security controls for the cloud provider

Return ONLY the JSON array. No markdown, no explanation outside the JSON."""

            ai_response = call_ai(system, prompt, max_tokens=2000)
            try:
                json_match = re.search(r'\[.*\]', ai_response, re.DOTALL)
                if json_match:
                    ai_findings = json.loads(json_match.group())
                    ai_findings.sort(key=lambda x: severity_order(x["severity"]))
            except Exception:
                ai_findings = []

    all_findings = static_findings + ai_findings
    all_findings.sort(key=lambda x: severity_order(x["severity"]))
    score = calculate_score(all_findings)

    st.markdown("---")
    st.markdown("## 📊 Resultado da Análise")

    # Score + summary
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        color = score_color(score)
        label = score_label(score)
        st.markdown(f"""
        <div class="score-box">
            <div class="score-num {color}">{score}</div>
            <div style="color:#8b949e;font-size:0.8rem">Security Score</div>
            <div style="color:#c9d1d9;font-size:0.9rem;font-weight:bold">{label}</div>
        </div>
        """, unsafe_allow_html=True)

    counts = {s: sum(1 for f in all_findings if f["severity"] == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    for col, (sev, color, icon) in zip([c2, c3, c4, c5], [
        ("CRITICAL", "#e74c3c", "🔴"),
        ("HIGH",     "#e67e22", "🟠"),
        ("MEDIUM",   "#f1c40f", "🟡"),
        ("LOW",      "#2ecc71", "🟢"),
    ]):
        with col:
            st.markdown(f"""
            <div class="score-box">
                <div style="font-size:2rem;font-weight:900;color:{color}">{counts[sev]}</div>
                <div style="color:#8b949e;font-size:0.8rem">{icon} {sev}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # Findings
    if not all_findings:
        st.success("✅ Nenhum problema encontrado! Código está seguindo as boas práticas.")
    else:
        st.markdown(f"### 🔎 {len(all_findings)} problema(s) encontrado(s)")

        sev_map = {
            "CRITICAL": ("critical", "🔴 CRITICAL"),
            "HIGH":     ("high",    "🟠 HIGH"),
            "MEDIUM":   ("medium",  "🟡 MEDIUM"),
            "LOW":      ("low",     "🟢 LOW"),
            "INFO":     ("info",    "🔵 INFO"),
        }

        for i, f in enumerate(all_findings):
            css, label = sev_map.get(f["severity"], ("info", f["severity"]))
            source_badge = "🤖 IA" if f.get("source") == "ai" else "📏 Regra"
            st.markdown(f"""
            <div class="finding {css}">
                <b>{label}</b> &nbsp;
                <code style="font-size:0.75rem">{f['rule_id']}</code> &nbsp;
                <span style="font-size:0.75rem;opacity:0.7">{source_badge}</span><br>
                <b>{f['name']}</b><br>
                <span style="opacity:0.85">{f['message']}</span>
                {"<br><br><b>✅ Correção:</b><br><code>" + f['fix'] + "</code>" if show_fixes and f.get('fix') else ""}
            </div>
            """, unsafe_allow_html=True)

    # AI Recommendations
    if ai_analysis and all_findings:
        st.markdown("---")
        st.markdown("### 🤖 Recomendações Gerais da IA")
        lang_str = "em português brasileiro" if lang == "Português" else "in English"
        with st.spinner("Gerando recomendações gerais..."):
            system2 = f"You are a cloud security expert. Respond {lang_str}. Be concise and practical."
            prompt2 = f"""Based on these {len(all_findings)} findings in Terraform code, 
give 3 prioritized strategic recommendations to improve overall security posture.
Be specific and actionable. Maximum 5 lines per recommendation.

Findings summary:
{json.dumps([{'severity': f['severity'], 'name': f['name']} for f in all_findings], indent=2)}"""
            recs = call_ai(system2, prompt2, max_tokens=800)
        st.markdown(f'<div class="finding info">{recs}</div>', unsafe_allow_html=True)

    # Export
    st.markdown("---")
    report = {
        "scan_date":     datetime.now().isoformat(),
        "security_score": score,
        "total_findings": len(all_findings),
        "by_severity":    counts,
        "findings":       all_findings,
    }
    st.download_button(
        "⬇️ Exportar relatório JSON",
        data=json.dumps(report, indent=2, ensure_ascii=False),
        file_name=f"iac-scan-{datetime.now().strftime('%Y%m%d-%H%M')}.json",
        mime="application/json",
    )
