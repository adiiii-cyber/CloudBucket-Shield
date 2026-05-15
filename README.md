# CloudBucket-Shield: S3 Security Auditor 🛡️

## Overview
A lightweight, automated Cloud Security Posture Management (CSPM) tool built with Python and `boto3`. This script audits AWS S3 environments to identify potential vulnerabilities, specifically checking for misconfigured Public Access Blocks and missing Server-Side Encryption (SSE).

## Features
* **Automated Enumeration:** Scans all S3 buckets within the authenticated AWS environment.
* **Vulnerability Detection:** Flags buckets with disabled "Block Public Access" settings.
* **Encryption Verification:** Validates the presence of Server-Side Encryption (SSE-S3/KMS).
* **Audit Reporting:** Generates a structured CSV report (`audit_report.csv`) for ingestion into security dashboards.

## Security & Architecture Principles
* **Principle of Least Privilege (PoLP):** Designed to run via a restricted IAM Bot user provisioned strictly with `AmazonS3ReadOnlyAccess`.
* **Zero-Spend FinOps:** Developed and tested within an environment governed by strict Zero-Spend AWS Budgets.
* **Operational Security (OpSec):** Built-in `.gitignore` prevents accidental leakage of generated audit findings and local AWS credentials.

## Usage
*(Execution requires configured AWS CLI credentials with appropriate IAM read permissions)*

```bash
# Install requirements
pip install boto3

# Run the auditor
python bucket_auditor.py
