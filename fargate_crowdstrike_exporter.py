"""
Open-Source CrowdStrike Spotlight Fargate Exporter
--------------------------------------------------
A Fargate-ready Python script that exports CrowdStrike Spotlight vulnerabilities, 
calculates SLA compliance metrics, and uploads the raw dumps and summary reports 
directly to Amazon S3. 

Environment Variables:
- AWS_REGION: (Default: us-east-1)
- AWS_SECRET_NAME: Name of the secret in AWS Secrets Manager containing API keys.
- S3_BUCKET_NAME: The destination S3 bucket for the CSV reports.
- TARGET_HOST_GROUPS: Comma-separated list of Host Groups for the summary report.
- SLA_CRITICAL_DAYS: (Default: 15)
- SLA_HIGH_DAYS: (Default: 30)

Expected AWS Secret Manager JSON format:
{
    "FALCON_CLIENT_ID": "your_id",
    "FALCON_CLIENT_SECRET": "your_secret"
}
"""

import os
import csv
import json
import time
import logging
import threading
from datetime import datetime, timezone, timedelta
import requests
import boto3
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# CONFIGURATION & SETUP
# ==========================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_WORKERS = 15
RATE_LIMIT_DELAY = 0.05
BASE_URL = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com").rstrip('/')

# --- ENVIRONMENT ABSTRACTION (No hardcoded org data) ---
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_SECRET_NAME = os.getenv("AWS_SECRET_NAME")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
S3_PREFIX = os.getenv("S3_PREFIX", "crowdstrike/spotlight")

SLA_CRITICAL_DAYS = int(os.getenv("SLA_CRITICAL_DAYS", 15))
SLA_HIGH_DAYS = int(os.getenv("SLA_HIGH_DAYS", 30))

env_groups = os.getenv("TARGET_HOST_GROUPS", "Linux Servers,Windows Servers,Workstations")
TARGET_HOST_GROUPS = [g.strip() for g in env_groups.split(",")]

# ==========================================
# AWS & CROWDSTRIKE AUTHENTICATION
# ==========================================
AUTH_STATE = {'client_id': None, 'client_secret': None, 'token': None, 'expires_at': 0}
TOKEN_LOCK = threading.Lock()

def fetch_aws_secrets():
    """Retrieves CrowdStrike API credentials dynamically from AWS Secrets Manager."""
    if not AWS_SECRET_NAME:
        # Fallback to local environment variables if Secrets Manager isn't configured
        AUTH_STATE['client_id'] = os.getenv('FALCON_CLIENT_ID')
        AUTH_STATE['client_secret'] = os.getenv('FALCON_CLIENT_SECRET')
        if not AUTH_STATE['client_id']:
            raise ValueError("Missing AWS_SECRET_NAME or local FALCON_CLIENT_ID env variables.")
        return

    logging.info(f"🔐 Fetching credentials from AWS Secrets Manager: {AWS_SECRET_NAME}")
    client = boto3.client('secretsmanager', region_name=AWS_REGION)
    try:
        response = client.get_secret_value(SecretId=AWS_SECRET_NAME)
        secret_dict = json.loads(response['SecretString'])
        AUTH_STATE['client_id'] = secret_dict.get('FALCON_CLIENT_ID')
        AUTH_STATE['client_secret'] = secret_dict.get('FALCON_CLIENT_SECRET')
    except ClientError as e:
        logging.error(f"❌ Failed to retrieve AWS Secret: {e}")
        raise

def get_valid_headers():
    global AUTH_STATE
    with TOKEN_LOCK:
        if time.time() > AUTH_STATE['expires_at'] - 60:
            url = f"{BASE_URL}/oauth2/token"
            payload = {'client_id': AUTH_STATE['client_id'], 'client_secret': AUTH_STATE['client_secret']}
            response = requests.post(url, data=payload)
            response.raise_for_status()
            AUTH_STATE['token'] = response.json()['access_token']
            AUTH_STATE['expires_at'] = time.time() + 1740 
    return {'Authorization': f"Bearer {AUTH_STATE['token']}"}

# ==========================================
# DATA LOADING 
# ==========================================
def load_accounts():
    accounts = {}
    if os.path.exists("accounts.csv"):
        with open("accounts.csv", mode='r', encoding='utf-8-sig') as f:
            for row in csv.reader(f):
                if row and row[0].strip().isdigit():
                    accounts[row[0].strip().zfill(12)] = {
                        'BusinessUnit': row[1].strip() if len(row) > 1 else "Unknown",
                        'Leader': row[2].strip() if len(row) > 2 else "Unknown"
                    }
    return accounts

def load_exclusions():
    exclusions = {'accounts': set(), 'hosts': set(), 'ids': set()}
    if os.path.exists("exclude.txt"):
        with open("exclude.txt", mode='r', encoding='utf-8-sig') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                if line.startswith('i-'): exclusions['hosts'].add(line.lower())
                elif line.startswith('ACCT:'): exclusions['accounts'].add(line.split(':', 1)[1].strip())
                elif line.startswith('HOST:'): exclusions['hosts'].add(line.split(':', 1)[1].strip().lower())
                elif line.startswith('ID:'): exclusions['ids'].add(line.split(':', 1)[1].strip())
    return exclusions

# ==========================================
# CROWDSTRIKE API WORKERS
# ==========================================
def api_request_with_retry(method, url, params=None, json_data=None):
    max_retries = 5
    for attempt in range(max_retries):
        time.sleep(RATE_LIMIT_DELAY)
        headers = get_valid_headers() 
        try:
            if method == 'GET': response = requests.get(url, headers=headers, params=params)
            else: response = requests.post(url, headers=headers, json=json_data)
            if response.status_code == 429:
                time.sleep(2 ** attempt)
                continue
            response.raise_for_status()
            return response.json()
        except Exception:
            if attempt == max_retries - 1: return None

def fetch_vuln_details_chunk(chunk):
    url = f"{BASE_URL}/spotlight/entities/vulnerabilities/v2"
    data = api_request_with_retry('GET', url, params={'ids': chunk})
    pruned_vulns = []
    if not data or 'resources' not in data: return pruned_vulns
    now = datetime.now(timezone.utc)
    
    for v in data['resources']:
        if v.get('suppression_info', {}).get('is_suppressed', False): continue

        cvss_sev = v.get('cve', {}).get('severity', v.get('severity', 'Unknown')).capitalize()
        exprt_sev = v.get('cve', {}).get('exprt_rating', 'Unknown').capitalize()
        severity = exprt_sev if exprt_sev not in ['Unknown', 'None', ''] else cvss_sev
        
        if severity not in ['Critical', 'High']: continue
            
        created_str = v.get('created_timestamp')
        sla_status = "Within SLA"
        age_days = 0
        
        if created_str:
            try:
                created_dt = datetime.strptime(created_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                age_days = (now - created_dt).days
                if severity == 'Critical':
                    if age_days > SLA_CRITICAL_DAYS: sla_status = f"Out of SLA (>{SLA_CRITICAL_DAYS} Days)"
                    elif (SLA_CRITICAL_DAYS - 6) <= age_days <= SLA_CRITICAL_DAYS: sla_status = f"Approaching SLA"
                elif severity == 'High':
                    if age_days > SLA_HIGH_DAYS: sla_status = f"Out of SLA (>{SLA_HIGH_DAYS} Days)"
                    elif (SLA_HIGH_DAYS - 6) <= age_days <= SLA_HIGH_DAYS: sla_status = f"Approaching SLA"
            except ValueError: pass

        host_info = v.get('host_info', {})
        groups = [g.get('name', 'Unknown') if isinstance(g, dict) else str(g) for g in host_info.get('groups', [])]
        if not groups: groups = ['Unknown']
        
        internet_exposure = str(host_info.get('internet_exposure', 'Unknown')).lower()
        is_exposed = internet_exposure in ['exposed', 'online', 'yes', 'true']
        
        rem_ids = v.get('remediation', {}).get('ids', [])
        
        pruned_vulns.append({
            'Vuln_ID': v.get('id', 'Unknown'), 'CVE': v.get('cve', {}).get('id', 'Unknown'),
            'Hostname': host_info.get('hostname', 'Unknown'), 
            'Cloud_Account_ID': host_info.get('service_provider_account_id', 'Unknown'),
            'Host_Group': " | ".join(groups), '_Host_Groups_List': groups,
            'Severity': severity, 'Age_Days': age_days, 'Is_Exposed': is_exposed,
            'SLA_Status': sla_status, 'Remediation_ID': rem_ids[0] if rem_ids else None, 
            'Remediation': 'No fix available'
        })
    return pruned_vulns

def fetch_remediations_chunk(chunk):
    url = f"{BASE_URL}/spotlight/entities/remediations/v2"
    data = api_request_with_retry('GET', url, params={'ids': chunk})
    remediations = {}
    if data and 'resources' in data:
        for rem in data['resources']:
            remediations[rem['id']] = rem.get('action_and_reference') or rem.get('title') or 'No fix available'
    return remediations

# ==========================================
# MAIN EXPORT LOGIC
# ==========================================
def calculate_metrics(vulns, sla_crit, sla_high):
    metrics = {
        'Total Critical Vulns': 0, 'Total High Vulns': 0,
        f'Critical Vulns > {sla_crit} Days': 0, f'High Vulns > {sla_high} Days': 0,
        'Risk Closed (Last 24h)': 0
    }
    for v in vulns:
        if v.get('_closed_flag'):
            metrics['Risk Closed (Last 24h)'] += 1
            continue
            
        sev = v['Severity']
        if sev == 'Critical':
            metrics['Total Critical Vulns'] += 1
            if 'Out of SLA' in v['SLA_Status']: metrics[f'Critical Vulns > {sla_crit} Days'] += 1
        elif sev == 'High':
            metrics['Total High Vulns'] += 1
            if 'Out of SLA' in v['SLA_Status']: metrics[f'High Vulns > {sla_high} Days'] += 1
    return metrics

def generate_reports_and_upload(active_vulns, excluded_vulns, closed_vulns, accounts_map):
    date_str = datetime.now().strftime("%Y%m%d")
    generated_files = []
    
    # 1. FULL RAW VULN DUMP
    headers = ['Vuln_ID', 'CVE', 'Hostname', 'Cloud_Account_ID', 'Host_Group', 'Severity', 'SLA_Status', 'Remediation', 'Is_Exposed', 'Age_Days']
    dump_filename = f"all_vulnerabilities_{date_str}.csv"
    with open(dump_filename, "w", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows([{k: v[k] for k in headers} for v in active_vulns])
    generated_files.append(dump_filename)
            
    # 2. EXCLUSION AUDIT
    if excluded_vulns:
        ex_filename = f"exclusions_{date_str}.csv"
        ex_headers = headers + ['Exclusion_Reason']
        with open(ex_filename, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=ex_headers)
            writer.writeheader()
            for v in excluded_vulns:
                v_out = {k: v[k] for k in headers}
                v_out['Exclusion_Reason'] = v['Exclusion_Reason']
                writer.writerow(v_out)
        generated_files.append(ex_filename)

    # 3. SUMMARY DASHBOARDS
    for v in closed_vulns: v['_closed_flag'] = True
    combined_vulns = active_vulns + closed_vulns

    cloud_rows = []
    for acc_id, acct_info in accounts_map.items():
        acc_vulns = [v for v in combined_vulns if v['Cloud_Account_ID'] == acc_id]
        row = {'Cloud Account ID': acc_id, 'Business Unit': acct_info['BusinessUnit'], 'BU Leader': acct_info['Leader']}
        row.update(calculate_metrics(acc_vulns, SLA_CRITICAL_DAYS, SLA_HIGH_DAYS))
        cloud_rows.append(row)
        
    summary_headers = list(cloud_rows[0].keys()) if cloud_rows else []
    
    if cloud_rows:
        cloud_filename = f"cloud_vulnerability_summary_{date_str}.csv"
        with open(cloud_filename, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=summary_headers)
            writer.writeheader()
            writer.writerows(cloud_rows)
        generated_files.append(cloud_filename)

    # AWS S3 UPLOAD
    if S3_BUCKET_NAME:
        logging.info(f"☁️ Uploading to S3 Bucket: {S3_BUCKET_NAME}...")
        s3_client = boto3.client('s3', region_name=AWS_REGION)
        for file in generated_files:
            s3_key = f"{S3_PREFIX}/{date_str}/{file}"
            try:
                s3_client.upload_file(file, S3_BUCKET_NAME, s3_key)
                logging.info(f"  --> Uploaded: {s3_key}")
            except ClientError as e:
                logging.error(f"❌ S3 Upload Failed: {e}")
    else:
        logging.info("ℹ️ S3_BUCKET_NAME not set. Files generated locally.")

# ==========================================
# ORCHESTRATION
# ==========================================
def main():
    fetch_aws_secrets()
    accounts_map = load_accounts()
    exclusions = load_exclusions()
    
    logging.info("⏳ Phase 1: Fetching Open and Closed Vulnerabilities...")
    url = f"{BASE_URL}/spotlight/queries/vulnerabilities/v1"
    
    # Open Vulns
    all_vuln_ids, after_token = [], None
    while True:
        data = api_request_with_retry('GET', url, params={'filter': "status:'open'+suppression_info.is_suppressed:false", 'limit': 400, 'after': after_token})
        if not data or 'resources' not in data: break
        all_vuln_ids.extend(data['resources'])
        after_token = data.get('meta', {}).get('pagination', {}).get('after')
        if not after_token: break

    # Closed Vulns (Last 24h)
    yesterday_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    closed_vuln_ids, after_token = [], None
    while True:
        data = api_request_with_retry('GET', url, params={'filter': f"status:'closed'+closed_timestamp:>'{yesterday_str}'", 'limit': 400, 'after': after_token})
        if not data or 'resources' not in data: break
        closed_vuln_ids.extend(data['resources'])
        after_token = data.get('meta', {}).get('pagination', {}).get('after')
        if not after_token: break

    logging.info("⏳ Phase 2: Fetching full details via parallel processing...")
    raw_pruned_vulnerabilities, unique_rem_ids = [], set()
    
    chunks = [all_vuln_ids[i:i + 400] for i in range(0, len(all_vuln_ids), 400)]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for future in as_completed({executor.submit(fetch_vuln_details_chunk, c): c for c in chunks}):
            res = future.result()
            raw_pruned_vulnerabilities.extend(res)
            unique_rem_ids.update(v['Remediation_ID'] for v in res if v['Remediation_ID'])

    raw_closed_vulnerabilities = []
    if closed_vuln_ids:
        closed_chunks = [closed_vuln_ids[i:i + 400] for i in range(0, len(closed_vuln_ids), 400)]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for future in as_completed({executor.submit(fetch_vuln_details_chunk, c): c for c in closed_chunks}):
                raw_closed_vulnerabilities.extend(future.result())

    if unique_rem_ids:
        remediation_dict = {}
        rem_list = list(unique_rem_ids)
        rem_chunks = [rem_list[i:i + 400] for i in range(0, len(rem_list), 400)]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for future in as_completed({executor.submit(fetch_remediations_chunk, c): c for c in rem_chunks}):
                remediation_dict.update(future.result())

        for v in raw_pruned_vulnerabilities:
            if v['Remediation_ID'] in remediation_dict:
                v['Remediation'] = remediation_dict[v['Remediation_ID']]

    logging.info("🚫 Filtering vulnerabilities against exclusions...")
    active_vulns, excluded_vulns = [], []
    for v in raw_pruned_vulnerabilities:
        drop_reason = None
        hostname_lower = v['Hostname'].lower()

        if v['Vuln_ID'] in exclusions['ids']: drop_reason = "Vuln ID matched exclusion"
        elif v['Cloud_Account_ID'] in exclusions['accounts']: drop_reason = "Account matched exclusion"
        elif not v['Remediation_ID'] or "no fix" in v['Remediation'].lower(): drop_reason = "No patch available"
        else:
            for ex_host in exclusions['hosts']:
                if ex_host in hostname_lower:
                    drop_reason = f"Hostname matched '{ex_host}'"
                    break
            
        if drop_reason:
            v['Exclusion_Reason'] = drop_reason
            excluded_vulns.append(v)
        else: active_vulns.append(v)
            
    generate_reports_and_upload(active_vulns, excluded_vulns, raw_closed_vulnerabilities, accounts_map)

if __name__ == "__main__":
    main()
