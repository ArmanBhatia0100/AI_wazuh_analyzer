# Groq-Powered Wazuh AI Alert Analyzer

An AI-assisted SOC alert triage tool built with **Python, Wazuh, Groq, and the OpenAI Python SDK**. It analyzes Wazuh JSON alerts using a large language model and produces structured investigation guidance in a readable terminal dashboard.

## 1. Project Overview

Security analysts often need to review large volumes of security alerts, understand the evidence, assess potential severity, and determine the next investigation steps.

This project explores how a large language model can assist with the initial triage process.

The tool takes a Wazuh alert in JSON format, sends the alert to a Groq-hosted language model, and returns a structured analysis containing:

- Alert classification
- Incident summary
- Suggested severity and confidence
- Observed evidence
- Potential hypotheses
- MITRE ATT&CK technique mapping, when supported
- Recommended investigation steps
- Missing information
- Analyst review requirement

The results are displayed in the terminal using Rich and saved as a JSON report.

**Important:** This is an AI-assisted analysis prototype. It does not replace a SOC analyst or independently determine whether an incident is genuine.

## 2. Project Objectives

- Understand the structure of Wazuh security alerts.
- Integrate a large language model into a Python security workflow.
- Use Groq's OpenAI-compatible API interface.
- Convert unstructured AI responses into structured JSON.
- Separate observed evidence from AI-generated hypotheses.
- Generate actionable investigation recommendations.
- Build a practical cybersecurity project suitable for a SOC analyst portfolio.

## 3. Technology Stack

| Technology | Purpose |
|---|---|
| Python 3 | Application development |
| Wazuh | Security monitoring and alert generation |
| Groq API | Hosted AI inference |
| OpenAI Python SDK | API client using Groq's compatible endpoint |
| GPT-OSS 20B | Language model used for alert analysis |
| Rich | Terminal formatting and dashboard |
| JSON | Alert input and analysis output |
| Ubuntu Linux | Development environment |

## 4. Architecture

```text
       Wazuh Manager
             |
             v
       Wazuh Alert JSON
             |
             v
    Python Alert Analyzer
             |
             v
       Groq API Request
             |
             v
       GPT-OSS 20B Model
             |
             v
     Structured JSON Analysis
             |
       +-----+------+
       |            |
       v            v
  Rich Terminal   JSON Report
   Dashboard       Output
       |            |
       +------+-----+
              |
              v
       Human Analyst Review
```

## 5. AI Analysis Output

The analyzer is designed to return the following JSON structure:

```json
{
  "classification": "Potential Brute Force",
  "summary": "Multiple failed authentication attempts were observed.",
  "severity": "Medium",
  "confidence": "High",
  "evidence": [
    "Repeated failed login events",
    "Source IP address recorded in the alert"
  ],
  "hypotheses": [
    "The activity may indicate a brute-force attempt."
  ],
  "mitre_technique": "T1110 - Brute Force",
  "investigation_steps": [
    "Review authentication logs.",
    "Identify the source IP address.",
    "Check for successful authentication events."
  ],
  "missing_information": [
    "Whether any login attempt was successful."
  ],
  "analyst_decision": "Requires human review"
}
```

*Illustrative example only. Actual output depends on the input alert and model response.*

## 6. Analysis Rules

The system prompt instructs the model to follow these principles:

1. Do not invent evidence that is not present in the alert.
2. Separate observed facts from hypotheses.
3. Do not claim an attack was successful without supporting evidence.
4. Use appropriate severity and confidence levels.
5. Suggest MITRE ATT&CK techniques only when supported by the available evidence.
6. Identify missing information required for further investigation.
7. Require human review before an incident decision is made.

These instructions guide the model but do not guarantee factual accuracy. AI-generated results must be independently validated.

## 7. Terminal Dashboard

The Rich library formats the analysis into readable terminal sections.

The dashboard displays:

- Original Wazuh alert metadata
- AI classification
- Severity and confidence
- MITRE ATT&CK mapping
- Alert summary
- Evidence
- Hypotheses
- Investigation recommendations
- Missing information
- Human review status

## 8. Installation and Setup

### Prerequisites

- Ubuntu Linux
- Python 3.10 or later
- Groq API key
- A Wazuh alert JSON file

### Step 1: Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/wazuh-groq-ai-analyzer.git
cd wazuh-groq-ai-analyzer
```

### Step 2: Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install dependencies

```bash
pip install openai rich
```

### Step 4: Configure the Groq API key

Obtain an API key from the Groq developer console.

Set it as an environment variable:

```bash
export GROQ_API_KEY="your_groq_api_key"
```

Avoid hardcoding API keys in Python files or committing them to GitHub.

### Step 5: Run the analyzer

```bash
python3 wazuh_ai_analyzer.py alerts.json
```

Replace `alerts.json` with the path to your Wazuh alert file.

## 9. Example Input

A simplified Wazuh alert:

```json
{
  "timestamp": "2026-11-18T14:30:00.000+0000",
  "rule": {
    "id": "5710",
    "level": 10,
    "description": "Multiple failed login attempts"
  },
  "agent": {
    "id": "001",
    "name": "ubuntu-server"
  },
  "data": {
    "srcip": "192.168.1.100",
    "dstuser": "admin"
  }
}
```

The analyzer submits the alert for AI-assisted interpretation and displays the resulting structured analysis.

## 10. Project Structure

```text
wazuh-groq-ai-analyzer/
│
├── wazuh_ai_analyzer.py
├── alerts.json
├── alerts_analysis.json
├── requirements.txt
├── .gitignore
└── README.md
```

Example `requirements.txt`:

```text
openai
rich
```

Example `.gitignore`:

```text
venv/
.env
__pycache__/
*.pyc
```

Do not commit real security alerts containing sensitive hostnames, usernames, IP addresses, tokens, or other identifying information.

## 11. Security Considerations

- Treat alert content as untrusted input.
- Do not expose API keys in source code or GitHub.
- Sanitize sensitive information before sending alerts to an external API.
- Review your organization's data-handling requirements before using external AI services.
- Validate AI-generated evidence and recommendations against the original logs.
- Do not automate blocking, account disabling, or other response actions based solely on model output.

## 12. Current Limitations

This is an initial file-based prototype.

Current limitations include:

- Requires a manually supplied JSON alert file.
- Does not continuously monitor Wazuh alerts.
- Does not correlate multiple alerts.
- Does not maintain investigation history or analyst feedback.
- Does not independently validate AI-generated evidence.
- Does not execute recommended investigation steps.
- Requires human review of all AI-generated analysis.
- Depends on Groq API availability and model compatibility.

## 13. Future Improvements

| Improvement | Objective |
|---|---|
| Live Wazuh integration | Process new alerts automatically |
| Alert deduplication | Avoid repeatedly analyzing identical alerts |
| Local validation | Verify evidence against original alert fields |
| MITRE ATT&CK integration | Improve technique mapping validation |
| Alert correlation | Identify patterns across multiple alerts |
| Analyst feedback | Record corrections and improve evaluation |
| Streamlit dashboard | Build a web-based investigation interface |
| Local LLM support | Explore privacy-focused local inference |

## 14. What I Learned

This project provides practical experience with:

- Wazuh alert structure and security event analysis
- Python automation and JSON processing
- REST API integration
- OpenAI-compatible API clients
- Prompt design for security analysis
- Structured AI output
- MITRE ATT&CK concepts
- SOC alert triage and investigation workflows
- Linux development and environment configuration

## 15. Disclaimer

This project is intended for educational and portfolio purposes.

AI-generated classifications, severity assessments, hypotheses, and recommendations may be inaccurate or incomplete. All findings must be validated by a qualified analyst before being used for operational security decisions.

## 16. Author

**Arman Bhatia**

Cybersecurity | SOC Analysis | Security Operations | Python Automation

