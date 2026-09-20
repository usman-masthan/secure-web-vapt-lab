# Enterprise Security Fusion & Automation Architecture

This architecture diagram illustrates how vulnerability assessment data from tools like OWASP ZAP and Nmap integrates into an **Enterprise Security Operations & Fusion Centre** (such as London Stock Exchange Group's Fusion environment). It demonstrates the transition from raw vulnerability scanning to automated data ingestion, SIEM normalization, SOAR workflow execution, and multi-discipline operational reporting.

```mermaid
flowchart TD
    subgraph INGEST["1. Telemetry & Vulnerability Sources"]
        S1["Dynamic App Scanners (ZAP / DAST)"]
        S2["Network Discovery (Nmap / Port Scans)"]
        S3["Code Repositories (SAST / SCA)"]
        S4["Threat Intel & Fusion Feeds"]
    end

    subgraph ENGINE["2. Security Engineering & Automation Pipeline"]
        direction TB
        P1["Python Ingestion Engine (parse_zap_findings.py)"]
        P2["Heuristic False-Positive Filter & De-duplication"]
        P3["Schema Normalization (Splunk CIM / CEF / JSON)"]
        P1 --> P2 --> P3
    end

    subgraph SIEM_SOAR["3. Security Operations & Fusion Core"]
        direction TB
        F1["Enterprise SIEM (Splunk Enterprise Security)"]
        F2["SOAR Platform (Tines / Cortex XSOAR)"]
        F3["Cross-Discipline Fusion Hub\n(Cyber, Fraud, Physical, Intel)"]
        F1 <--> F2
        F2 <--> F3
    end

    subgraph ACTION["4. Automated Action & Reporting Products"]
        direction TB
        A1["Automated Ticketing (Jira / ServiceNow ITSM)"]
        A2["Automated Retesting Engine (verify_headers.py)"]
        A3["Executive & Operational Dashboards (Power BI / Splunk)"]
        A4["Fusion Threat Briefings & SLA Tracking"]
    end

    INGEST --> ENGINE
    ENGINE --> SIEM_SOAR
    SIEM_SOAR --> ACTION

    style INGEST fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style ENGINE fill:#fff8e1,stroke:#ffa000,stroke-width:2px
    style SIEM_SOAR fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style ACTION fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
```

---

## Operational Mechanics & Value Proposition

### 1. Data Normalization via Splunk CIM
Raw scanner outputs arrive in disparate vendor-specific formats (ZAP XML/JSON, Nmap text banners, Nessus XML). The Python automation parser standardizes all incoming events into the **Splunk Vulnerabilities Data Model**:
- Fields: `dest`, `signature`, `severity`, `cvss`, `cve`, `vendor_product`, `status`, `false_positive_flag`.
- Benefit: Enables universal search queries, unified correlation, and multi-source analytics without re-engineering SPL searches.

### 2. Heuristic Triage & Noise Elimination
Before tickets or alerts reach human analysts, automated heuristics flag known false positives:
- Regex checks identifying WebSocket transport parameters (`sid=`) vs true auth tokens.
- Asset context lookups verifying whether the asset is external-facing or internal lab.
- Eliminates 30%+ of alert volume before human intervention.

### 3. Cross-Discipline Security Fusion
By centralizing vulnerability status within the Fusion Center:
- **Fraud Operations** can cross-reference exposed web endpoints against active account takeover attempts.
- **Threat Intelligence** correlates active vulnerabilities against emerging CVE threat campaigns.
- **Engineering Leadership** receives real-time visibility into Mean Time to Remediate (MTTR) and SLA compliance.

