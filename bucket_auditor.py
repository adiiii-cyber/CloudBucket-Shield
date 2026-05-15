import boto3
import csv
from botocore.exceptions import ClientError

def banner():
    print("-" * 60)
    print("    CloudBucket-Shield: S3 Security Auditor v1.2    ")
    print("-" * 60)

def audit_bucket_security(s3_client, bucket_name):
    # Dictionary to store this bucket's data
    finding = {"BucketName": bucket_name}
    
    # 1. Check Public Access Block
    try:
        public_access = s3_client.get_public_access_block(Bucket=bucket_name)
        is_public_blocked = all(public_access['PublicAccessBlockConfiguration'].values())
    except ClientError:
        is_public_blocked = False

    # 2. Check Encryption
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        is_encrypted = True
    except ClientError:
        is_encrypted = False

    # Store findings
    finding["PublicAccessBlocked"] = "SECURE" if is_public_blocked else "VULNERABLE"
    finding["Encryption"] = "ENCRYPTED" if is_encrypted else "NOT ENCRYPTED"
    
    print(f"[*] Scanned {bucket_name}: {finding['PublicAccessBlocked']} | {finding['Encryption']}")
    return finding

def run_scanner():
    s3 = boto3.client('s3')
    results = []
    
    try:
        response = s3.list_buckets()
        buckets = [b['Name'] for b in response.get('Buckets', [])]
        
        print(f"[+] Found {len(buckets)} bucket(s). Generating report...\n")
        
        for name in buckets:
            report_data = audit_bucket_security(s3, name)
            results.append(report_data)
            
        # Write to CSV
        with open('audit_report.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["BucketName", "PublicAccessBlocked", "Encryption"])
            writer.writeheader()
            writer.writerows(results)
            
        print(f"\n[!] Audit Complete. Report saved to: audit_report.csv")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    banner()cd
    run_scanner()