

````
# CrowdStrike Spotlight Enterprise Metrics & Fargate Exporter

A multi-threaded, memory-efficient Python utility designed to run natively within an AWS ECS Fargate task (or locally as a standalone command-line tool). 

It dynamically fetches vulnerable asset datasets from the CrowdStrike Falcon Spotlight API, enforces enterprise exclusion rules, correlates cloud accounts with line-of-business mappings, calculates strict SLA burndowns, and stores the resulting raw dumps and metrics summaries securely in an Amazon S3 data lake.

## Features
* **Fargate-Native Execution:** Eliminates hardcoded local credentials by securely fetching API secrets from AWS Secrets Manager and uploading output datasets directly to Amazon S3.
* **ExPRT Vulnerability Isolation:** Gracefully isolates and maps High and Critical threat profiles, filtering out CVSS noise dropped by CrowdStrike's AI engine (ExPRT).
* **Stateless 24h Burndown Metrics:** Automatically isolates vulnerabilities mitigated within the last 24 hours to track security engineering remediation performance (ROI).
* **Automated Patch Auditing:** Separates unpatchable/vendor-limited bugs into an independent audit track (`exclusions.csv`) so your remediation compliance percentages aren't artificially penalized.

---

## AWS Infrastructure Requirements

To run this tool inside an ECS Fargate task, ensure your Task Execution IAM Role has the following minimum permissions:

### 1. AWS Secrets Manager Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:SECRET_NAME"
        }
    ]
}
````

### **2\. Amazon S3 Data Bucket Policy**

JSON

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME/crowdstrike/*"
        }
    ]
}
```

## **Configuration Variables**

The runtime parameters are fully controlled via standardized environment variables.

| Variable Name | Required | Default | Description |
| :---- | :---- | :---- | :---- |
| AWS\_SECRET\_NAME | **Yes** | *None* | The name/path of the secret containing CrowdStrike API credentials. |
| S3\_BUCKET\_NAME | **Yes** | *None* | The destination S3 bucket name where reports are uploaded. |
| AWS\_REGION | No | us-east-1 | The AWS Region where Secrets Manager and S3 reside. |
| FALCON\_BASE\_URL | No | https://api.crowdstrike.com | Base URL for the Falcon platform (e.g., change for US-2 or EU clouds). |
| S3\_PREFIX | No | crowdstrike/spotlight | S3 key hierarchy/folder prefix structure. |
| SLA\_CRITICAL\_DAYS | No | 15 | Days allowed for a Critical item before it is flagged as breaching SLA. |
| SLA\_HIGH\_DAYS | No | 30 | Days allowed for a High item before it is flagged as breaching SLA. |
| TARGET\_HOST\_GROUPS | No | Linux Servers,Windows Servers | Comma-separated list of Host Groups to process summaries for. |

### **Expected AWS Secret Manager Format**

Your secret value must be stored as a valid JSON string matching these specific dictionary keys:

JSON

```
{
    "FALCON_CLIENT_ID": "your-crowdstrike-oauth-client-id",
    "FALCON_CLIENT_SECRET": "your-crowdstrike-oauth-client-secret"
}
```

## **Input Template Examples**

Place these mapping files in the root execution folder of the script. The script gracefully ignores missing parameters or empty fields.

### **accounts.csv**

Used to map raw 12-digit AWS Cloud Account IDs dynamically found inside CrowdStrike telemetry back to specific internal business units and engineering leads for accountability reports.

Code snippet

```
AccountID,BusinessUnit,BU_Leader
123456789012,Engineering-Platform,Jane Doe
987654321098,Digital-Marketing,John Smith
555566667777,Corporate-Finance,Alice Johnson
```

### **exclude.txt**

Used to completely filter specific items out of the main active dashboard. Supports custom comments (\#) and flags host names, distinct EC2 resource keys, explicit vulnerability tags, or entire enterprise accounts.

Plaintext

```
# Exclude isolated core database servers by specific hostname
HOST: prod-mysql-cluster-01
HOST: stage-legacy-app-server

# Exclude ephemeral, short-lived auto-scaling EC2 instances by ID
i-0a1b2c3d4e5f6g7h8
i-0987654321abcdef0

# Exclude entire sandbox or isolated laboratory AWS accounts
ACCT: 999900001111

# Exclude a known vendor-acknowledged vulnerability ID currently under exception review
ID: vuln_12345abcde
```

## **Generated Artifacts**

When executed, the script creates and syncs the following date-stamped (YYYYMMDD) reports to your S3 destination bucket under the defined prefix folder:

1. **all\_vulnerabilities\_\[date\].csv**  
   The comprehensive master database of all active, in-scope open risks across the enterprise. Includes detailed breakdowns of hostname, vulnerability age, and vulnerability identification parameters.  
2. **exclusions\_\[date\].csv**  
   An explicit audit trail tracking every single vulnerability dropped due to host/account filter rules, or unpatchable vendor gaps where no software remediation path exists.  
3. **cloud\_vulnerability\_summary\_\[date\].csv**  
   The structural high-level compliance dashboard grouping SLA breaches, critical-to-high risk visibility averages, and 24-hour closed burndown rates directly mapped by Cloud Account ID.

