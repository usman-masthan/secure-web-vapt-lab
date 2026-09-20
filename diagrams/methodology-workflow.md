# Assessment Methodology Workflow

This diagram illustrates the end-to-end lifecycle of the authorized VAPT assessment, tracking the flow from initial scoping and container setup to automated scanning, manual triage, false positive elimination, and retesting verification.

```mermaid
flowchart TD
    subgraph S1["1. Planning & Scoping"]
        A["Define RoE & Scope (127.0.0.1:3000)"] --> B["Deploy Isolated Docker Container"]
    end

    subgraph S2["2. Discovery & Reconnaissance"]
        B --> C["Nmap Service Discovery (-sV -p 3000)"]
        C --> D["Manual HTTP Banner Verification (curl -I)"]
    end

    subgraph S3["3. Automated Passive Scanning"]
        D --> E["Configure OWASP ZAP Intercepting Proxy"]
        E --> F["Manual Browsing & Traffic Generation"]
        F --> G["ZAP Passive Scanner Engine"]
        G --> H["10 Raw Automated Alerts Generated"]
    end

    subgraph S4["4. Triage & Deep Validation"]
        H --> I{"Manual Analysis & Triage"}
        I -->|"Regex Artifacts / Transport Params"| J["REJECT FALSE POSITIVES (30%)\n- ZAP-004: Socket.IO sid != Auth Token\n- ZAP-007: Webpack Timestamps != Secret"]
        I -->|"True Security Defects"| K["CONFIRM TRUE POSITIVES (30%)\n- ZAP-001: Missing CSP\n- ZAP-002: Permissive CORS (*)\n- ZAP-008: Missing nosniff"]
        I -->|"Env Constraints"| L["ENVIRONMENTAL NUANCES (20%)\n- ZAP-006: HSTS over HTTP\n- ZAP-005: Docker Bridge IP"]
        I -->|"Active Exploitation"| M["MANUAL PoCs (Uncovered by Manual Analysis)\n- VULN-01: SQLi Auth Bypass (CVSS 9.8)\n- VULN-02: Admin API Leak (CVSS 7.5)"]
    end

    subgraph S5["5. Reporting & Remediation"]
        K & M --> N["Author Actionable Remediation Reports"]
        N --> O["Engineering Applies Code & Proxy Fixes"]
    end

    subgraph S6["6. Verification & Retest"]
        O --> P["Automated Header & Payload Retest"]
        P --> Q["Verified Closed (Residual Risk: Low)"]
    end

    style J fill:#f8d7da,stroke:#f5c6cb,stroke-width:2px,color:#721c24
    style K fill:#d4edda,stroke:#c3e6cb,stroke-width:2px,color:#155724
    style M fill:#fff3cd,stroke:#ffeeba,stroke-width:2px,color:#856404
    style Q fill:#cce5ff,stroke:#b8daff,stroke-width:2px,color:#004085
```

