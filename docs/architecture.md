# ADPathFinder Architecture

## 1. Project Overview

ADPathFinder is an Active Directory discovery and security analysis tool designed to collect Active Directory information, analyze security configurations, identify risks, map relationships, and generate security reports.

## 2. Architecture

The project follows a modular architecture.

### Data Collection

The collectors gather information from the Active Directory environment.

Data collected includes:

- Domain information
- Users
- Groups
- Computers
- Organizational Units
- Group memberships

### Data Normalization

The normalizer converts collected information into a consistent format so that other modules can process it easily.

### Security Analysis

The analyzers examine collected data and identify security misconfigurations and potentially risky configurations.

### Relationship Analysis

The relationship engine maps connections between users, groups, computers, and other Active Directory objects.

### Risk Analysis

The risk engine assigns severity levels and prioritizes security findings.

### Reporting

The reporting module generates JSON and HTML reports.

### Dashboard

The dashboard provides a graphical interface for viewing domain information, security findings, risk summaries, and relationships.

## 3. Data Flow

Active Directory
→ Data Collection
→ Data Normalization
→ Security Analysis
→ Relationship Analysis
→ Risk Analysis
→ Reporting
→ GUI Dashboard

## 4. Technology Stack

- Python
- Streamlit
- JSON
- HTML
- Git
- pytest

## 5. Project Goals

- Simplify Active Directory security discovery
- Identify potentially risky configurations
- Analyze user and group relationships
- Prioritize security findings
- Generate understandable security reports
- Provide a graphical dashboard
