# ADPathFinder

**Active Directory Security Analysis and Risk Assessment Platform**

ADPathFinder is a modular cybersecurity project designed to analyze Active Directory environments, identify security weaknesses, map relationships between directory objects, and prioritize security findings based on risk.

The project focuses on building an automated security analysis platform that helps security professionals understand Active Directory configurations, privilege relationships, and potential security risks.

---

## Project Overview

Active Directory is widely used for centralized identity and access management in enterprise environments. Misconfigurations, excessive privileges, weak password policies, and improper group relationships can introduce significant security risks.

ADPathFinder aims to automate the analysis of Active Directory data and provide structured security findings that can help administrators and security professionals identify and prioritize these risks.

---

## Current Features

### 1. Active Directory Data Collection

Modular collectors for:

- Domain information
- User accounts
- Groups
- Computers
- Organizational Units

The current implementation uses structured JSON-based lab data to simulate Active Directory collection and analysis workflows.

---

### 2. Data Normalization

Converts collected Active Directory data into a standardized structure.

This helps maintain consistency across different data sources and makes the data easier to analyze.

---

### 3. Relationship Mapping

Analyzes relationships between Active Directory objects, including:

- User-to-group relationships
- Group membership relationships
- Computer-to-domain relationships
- Organizational Unit relationships

---

### 4. Security Analysis Engine

Identifies potential security weaknesses such as:

- Passwords that never expire
- Accounts that do not require passwords
- Disabled accounts
- Privileged group memberships
- Empty groups
- Large group memberships
- Potentially risky domain password policies

---

### 5. Privilege Analysis

Identifies users and groups associated with privileged Active Directory roles.

The analysis currently focuses on common privileged groups, including:

- Domain Admins
- Enterprise Admins
- Schema Admins
- Administrators
- Other configured privileged groups

---

### 6. Relationship-Based Security Analysis

Analyzes relationships between directory objects to identify security concerns such as:

- Privileged group membership
- Nested groups within privileged groups
- Large groups
- Empty groups

---

### 7. Risk Scoring

Security findings are assigned severity levels:

- Critical
- High
- Medium
- Low
- Informational

A risk scoring engine calculates an overall risk score based on the severity of identified findings.

---

### 8. Reporting

The project generates structured analysis results in JSON format.

Current reports include:

- Normalized Active Directory data
- Relationship information
- Security findings
- Risk assessment reports
- Relationship analysis findings

---

## Project Architecture

```text
ADPathFinder
│
├── Collectors
│   └── Collect Active Directory information
│
├── Normalizer
│   └── Standardize collected data
│
├── Relationship Engine
│   └── Map relationships between AD objects
│
├── Analyzers
│   └── Identify security weaknesses
│
├── Risk Engine
│   └── Calculate risk scores
│
├── Reporting
│   └── Generate structured reports
│
└── Dashboard
    └── Visualize security analysis results
```

---

## Technology Stack

- Python
- JSON
- Modular Python architecture
- Object-oriented programming
- Active Directory security concepts
- Risk-based security analysis

---

## Project Structure

```text
ADPathFinder/
│
├── adpathfinder/
│   ├── analyzers/
│   ├── collectors/
│   ├── core/
│   ├── dashboard/
│   ├── models/
│   ├── normalizer/
│   ├── relationships/
│   ├── reporting/
│   ├── risk/
│   └── utils/
│
├── config/
├── data/
│   ├── raw/
│   └── processed/
│
├── docs/
├── reports/
├── tests/
│
├── main.py
├── requirements.txt
└── README.md
```

---

## Current Development Status

### Completed

- [x] Project architecture and modular structure
- [x] Project initialization and environment setup
- [x] Data collection modules
- [x] JSON-based data loading
- [x] Domain data collection
- [x] User data collection
- [x] Group data collection
- [x] Computer data collection
- [x] Organizational Unit data collection
- [x] Data normalization
- [x] Relationship mapping
- [x] Data export
- [x] User security analysis
- [x] Group security analysis
- [x] Privilege analysis
- [x] Domain security analysis
- [x] Risk scoring engine
- [x] Relationship-based security analysis
- [x] JSON security reports

### In Progress

- [ ] Attack path discovery
- [ ] Advanced privilege relationship analysis
- [ ] Improved risk prioritization
- [ ] HTML reporting improvements
- [ ] Interactive dashboard
- [ ] Live Active Directory data collection
- [ ] Additional security analysis modules

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ADPathFinder.git
```

```bash
cd ADPathFinder
```

### 2. Create a Virtual Environment

Windows:

```powershell
python -m venv venv
```

Activate it:

```powershell
venv\Scripts\activate
```

Linux:

```bash
python3 -m venv venv
```

```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

Run the main analysis engine:

```bash
python main.py
```

Run individual tests:

```bash
python tests/test_collectors.py
```

```bash
python tests/test_normalization.py
```

```bash
python tests/test_security_analysis.py
```

```bash
python tests/test_relationship_analysis.py
```

---

## Output

Analysis results are generated under:

```text
data/processed/
```

Example output files:

```text
normalized_data.json
relationships.json
security_findings.json
risk_report.json
relationship_findings.json
```

---

## Security and Ethical Use

ADPathFinder is developed for educational purposes, authorized security assessments, and defensive Active Directory security analysis.

The project should only be used against Active Directory environments where the user has explicit authorization.

---

## Roadmap

- [ ] Attack Path Discovery Engine
- [ ] Advanced Privilege Escalation Relationship Analysis
- [ ] Risk Prioritization Improvements
- [ ] HTML Security Reports
- [ ] Interactive Security Dashboard
- [ ] Live Active Directory Integration
- [ ] Additional Security Checks
- [ ] Graph-Based Relationship Visualization
- [ ] Exportable Assessment Reports

---

## Author

**Lakhveer Singh**

B.Tech Computer Science and Engineering Student

Cybersecurity | Offensive Security | Active Directory Security | VAPT

---

## Disclaimer

This project is intended for educational and authorized security testing purposes only. The author is not responsible for misuse of this software.
