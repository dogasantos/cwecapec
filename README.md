# MITRE Data Update System - V2

This document provides a comprehensive overview of the redesigned MITRE data update system. The new implementation is more robust, reliable, and complete, addressing the shortcomings of the previous version by using official, version-agnostic data sources and creating a richer set of relationships between different cybersecurity knowledge bases.

## Key Improvements

The new system offers several significant advantages over the previous implementation:

- **Stable Data Sources**: It now uses official GitHub repositories and version-agnostic URLs for MITRE ATT&CK, CWE, and CAPEC data. This completely resolves the issue of broken links when new versions are released.

- **Comprehensive Data Model**: The system now parses the full STIX 2.1 data for MITRE ATT&CK, which includes not just techniques, but also groups (threat actors), software (malware and tools), and mitigations.

- **Rich Relationship Mapping**: A new `relationships_db.json` file is generated, providing explicit, bidirectional mappings between CWE, CAPEC, and ATT&CK. This allows for powerful cross-framework analysis.

- **Expanded ATT&CK Coverage**: The system now processes all three major ATT&CK domains: Enterprise, Mobile, and ICS, merging them into a unified dataset.

- **Improved Code Structure**: The Go application has been completely rewritten to be more modular, efficient, and easier to maintain. It no longer relies on parsing fragile Excel files and has no external dependencies.

- **Smarter Workflow**: The GitHub Actions workflow is now more intelligent. It only commits and pushes changes if the data has actually been updated, preventing empty commits.

## How It Works

The data update process is executed in four main stages:

1.  **CWE Processing**: Downloads the latest CWE (Common Weakness Enumeration) data as an XML file, parses it, and extracts the relationships between weaknesses and their corresponding CAPEC attack patterns.

2.  **CAPEC Processing**: Downloads the latest CAPEC (Common Attack Pattern Enumeration and Classification) data as an XML file. It parses the attack patterns, their relationships to CWEs, and their mappings to the MITRE ATT&CK framework.

3.  **MITRE ATT&CK Processing**: Downloads the latest STIX 2.1 JSON bundles for Enterprise, Mobile, and ICS ATT&CK. It processes thousands of STIX objects (techniques, groups, software, mitigations) and the relationships between them to build a comprehensive view of the ATT&CK knowledge base.

4.  **Relationship Building**: In the final stage, the system consolidates the information gathered from all sources to build and save the master relationship mappings between the different frameworks.

## Output Data Structure

The process generates several well-structured JSON files in the `resources/` directory:

| File Name                 | Description                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------------- |
| `cwe_db.json`             | Contains a dictionary of all CWEs, including their parent weaknesses and related CAPEC patterns.        |
| `capec_db.json`           | Contains a detailed dictionary of all CAPEC attack patterns, including their links to CWEs and ATT&CK.    |
| `attack_techniques_db.json` | A complete database of all ATT&CK techniques from all domains, enriched with their associated tactics, platforms, groups, and software. |
| `attack_groups_db.json`   | A database of threat actor groups (Intrusion Sets) and the techniques and software they use.            |
| `attack_software_db.json` | A database of malware and tools, linked to the techniques they implement and the groups that use them.  |
| `attack_mitigations_db.json`| A database of mitigations (Courses of Action) and the techniques they address.                          |
| `relationships_db.json`   | The master mapping file, providing clear, queryable links between CWE, CAPEC, and ATT&CK.             |
| `metadata.json`           | A small file containing the timestamp of the last successful update.                                    |

## Deliverables

Here are all the files you need to update your repository.

### 1. Go Application (`main.go`)

This is the completely rewritten Go application. It replaces your old `main.go` file.

### 2. Go Module File (`go.mod`)

This file defines the Go module. The new application has no external dependencies, so this file is very simple.

### 3. GitHub Actions Workflow (`.github/workflows/update_mitre.yml`)

This is the updated workflow file. It uses Go 1.23 and includes the logic to check for changes before committing. You should place this in your `.github/workflows/` directory.

## Next Steps

1.  **Replace `main.go`**: Update your repository with the new `main.go` file provided.
2.  **Add `go.mod`**: Add the new `go.mod` file to the root of your repository.
3.  **Update Workflow**: Replace your existing GitHub Actions workflow file with the new one.
4.  **Commit and Push**: Commit these changes to your repository.
5.  **Manual Trigger**: You can then manually trigger the workflow from the "Actions" tab of your repository to see it run immediately.
