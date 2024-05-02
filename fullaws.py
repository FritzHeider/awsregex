import os
import boto3
import re
import logging
import pdfplumber
import csv
import json
from io import BytesIO


regex_patterns = {
    "U.S. Social Security numbers": r"\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d))([-]?|\s{1})(?!00)\d\d\2(?!0000)\d{4}\b",
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Visa Credit Card": "4[0-9]{12}(?:[0-9]{3})?",
    "AWS Access Key ID Value": "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Access Key ID": "((\\\"|'|`)?((?i)aws)?_?((?i)access)_?((?i)key)?_?((?i)id)?(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\\\"|'|`)?)",
    "AWS Account ID": "((\\\"|'|`)?((?i)aws)?_?((?i)account)_?((?i)id)?(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?[0-9]{4}-?[0-9]{4}-?[0-9]{4}(\\\"|'|`)?)",
    "AWS Secret Access Key": "((\\\"|'|`)?((?i)aws)?_?((?i)secret)_?((?i)access)?_?((?i)key)?_?((?i)id)?(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?[A-Za-z0-9/+=]{40}(\\\"|'|`)?)",
    "AWS Session Token": "((\\\"|'|`)?((?i)aws)?_?((?i)session)?_?((?i)token)?(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?[A-Za-z0-9/+=]{16,}(\\\"|'|`)?)",
    "Artifactory": "(?i)artifactory.{0,50}(\\\"|'|`)?[a-zA-Z0-9=]{112}(\\\"|'|`)?",
    "CodeClimate": "(?i)codeclima.{0,50}(\\\"|'|`)?[0-9a-f]{64}(\\\"|'|`)?",
    "Facebook access token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Google (GCM) Service account": "((\\\"|'|`)?type(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?service_account(\\\"|'|`)?,?)",
    "Stripe API key": "(?:r|s)k_[live|test]_[0-9a-zA-Z]{24}",
    "Google OAuth Key": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google Cloud API Key": "AIza[0-9A-Za-z\\\\-_]{35}",
    "Google OAuth Access Token": "ya29\\\\.[0-9A-Za-z\\\\-_]+",
    "Picatic API key": "sk_[live|test]_[0-9a-z]{32}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "PayPal/Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Twilo API Key": "SK[0-9a-fA-F]{32}",
    "SendGrid API Key": "SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}",
    "MailGun API Key": "key-[0-9a-zA-Z]{32}",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{12}",
    "SSH Password": "sshpass -p.*['|\\\"]",
    "Outlook team": "(https\\\\://outlook\\\\.office.com/webhook/[0-9a-f-]{36}\\\\@)",
    "Sauce Token": "(?i)sauce.{0,50}(\\\"|'|`)?[0-9a-f-]{36}(\\\"|'|`)?",
    "Slack Token": "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "SonarQube Docs API Key": "(?i)sonar.{0,50}(\\\"|'|`)?[0-9a-f]{40}(\\\"|'|`)?",
    "HockeyApp": "(?i)hockey.{0,50}(\\\"|'|`)?[0-9a-f]{32}(\\\"|'|`)?",
    "Username and password in URI": "([\\w+]{1,24})(://)([^$<]{1})([^\\s\";]{1,}):([^$<]{1})([^\\s\";/]{1,})@[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,24}([^\\s]+)",
    "NuGet API Key": "oy2[a-z0-9]{43}",
    "StackHawk API Key": "hawk\\.[0-9A-Za-z\\-_]{20}\\.[0-9A-Za-z\\-_]{20}",
    "Contains a private key": "-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY",
    "WP-Config": "define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|\"].{10,120}['|\"]",
    "AWS cred file info": "(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\\/+]{20,40}",
    "Facebook Secret Key": "(?i)(facebook|fb)(.{0,20})?(?-i)['\\\"][0-9a-f]{32}['\\\"]",
    "Facebook Client ID": "(?i)(facebook|fb)(.{0,20})?['\\\"][0-9]{13,17}['\\\"]",
    "Twitter Secret Key": "(?i)twitter(.{0,20})?['\\\"][0-9a-z]{35,44}['\\\"]",
    "Twitter Client ID": "(?i)twitter(.{0,20})?['\\\"][0-9a-z]{18,25}['\\\"]",
    "Github Key": "(?i)github(.{0,20})?(?-i)['\\\"][0-9a-zA-Z]{35,40}['\\\"]",
    "Heroku API key": "(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
    "Linkedin Client ID": "(?i)linkedin(.{0,20})?(?-i)['\\\"][0-9a-z]{12}['\\\"]",
    "LinkedIn Secret Key": "(?i)linkedin(.{0,20})?['\\\"][0-9a-z]{16}['\\\"]",
    "Mastercard": "(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}",
    "amex": "3[47][0-9]{13}",
    "bitcoins": "^(0x)?[a-fA-F0-9]{64}$",
    "ethereum": "^(0x)?[a-fA-F0-9]{64}$",
    "Mnemonic phrase 12": "^(?:[a-zA-Z]+ ){11}[a-zA-Z]+$"
        # Add more patterns here as neededs
    }



  def search_content(s3, bucket_name, regex_patterns):
    """Search for the given regex patterns in all files of the bucket."""
    results = []
    try:
        for file_key in list_s3_objects(s3, bucket_name):
            obj = s3.get_object(Bucket=bucket_name, Key=file_key)
            file_content = obj['Body'].read()
            file_type = obj.get('ContentType', 'application/octet-stream')

            if 'text' in file_type or file_key.endswith('.txt'):
                file_text = file_content.decode('utf-8', errors='replace')
            elif 'application/pdf' in file_type or file_key.endswith('.pdf'):
                file_text = extract_text_from_pdf(file_content)
            elif 'text/csv' in file_type or file_key.endswith('.csv'):
                file_text = extract_text_from_csv(file_content)
            elif 'application/json' in file_type or file_key.endswith('.json'):
                file_text = extract_text_from_json(file_content)
            else:
                logging.info(f"Skipped unsupported file type: {file_key}")
                continue

            for name, regex in regex_patterns.items():
                matches = regex.findall(file_text)
                if matches:
                    results.append(f"{name}: Found {len(matches)} matches in {file_key}")
                else:
                    results.append(f"{name}: No matches found in {file_key}")
    except Exception as e:
        logging.error(f"An error occurred while processing files in {bucket_name}: {e}")
    return results

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_s3_client():
    """Create an S3 client using AWS credentials from environment variables."""
    session = boto3.Session(
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name='us-east-1'
    )
    return session.client('s3')

def list_s3_objects(s3, bucket_name):
    """List all objects in the specified S3 bucket handling pagination."""
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=bucket_name):
        for item in page.get('Contents', []):
            yield item['Key']

def extract_text_from_pdf(file_content):
    """Extract text from PDF file content using pdfplumber."""
    text = []
    with pdfplumber.open(BytesIO(file_content)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text.append(page_text)
    return '\n'.join(text)

def extract_text_from_csv(file_content):
    """Extract and return text from a CSV content."""
    text = []
    decoded_content = BytesIO(file_content).getvalue().decode('utf-8', errors='replace')
    csv_reader = csv.reader(decoded_content.splitlines())
    for row in csv_reader:
        text.append(','.join(row))
    return '\n'.join(text)

def extract_text_from_json(file_content):
    """Extract and return text from JSON content."""
    try:
        obj = json.loads(file_content.decode('utf-8', errors='replace'))
        text = json.dumps(obj)  # Convert JSON object to a string to search for patterns
        return text
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode JSON: {e}")
        return ""

def search_content(s3, bucket_name, regex_patterns):
    """Search for the given regex patterns in all files of the bucket."""
    results = []
    try:
        for file_key in list_s3_objects(s3, bucket_name):
            obj = s3.get_object(Bucket=bucket_name, Key=file_key)
            file_content = obj['Body'].read()
            file_type = obj.get('ContentType', 'application/octet-stream')

            if 'text' in file_type or file_key.endswith('.txt'):
                file_text = file_content.decode('utf-8', errors='replace')
            elif 'application/pdf' in file_type or file_key.endswith('.pdf'):
                file_text = extract_text_from_pdf(file_content)
            elif 'text/csv' in file_type or file_key.endswith('.csv'):
                file_text = extract_text_from_csv(file_content)
            elif 'application/json' in file_type or file_key.endswith('.json'):
                file_text = extract_text_from_json(file_content)
            else:
                logging.info(f"Skipped unsupported file type: {file_key}")
                continue

            for name, regex in regex_patterns.items():
                matches = regex.findall(file_text)
                if matches:
                    results.append(f"{name}: Found {len(matches)} matches in {file_key}")
                else:
                    results.append(f"{name}: No matches found in {file_key}")
    except Exception as e:
        logging.error(f"An error occurred while processing files in {bucket_name}: {e}")
    return results

def main():
    s3 = create_s3_client()
    bucket_name = input("Enter the S3 bucket name: ")
    

    results = search_content(s3, bucket_name, regex_patterns)
    output_directory = 'output'
    os.makedirs(output_directory, exist_ok=True)
    output_file_path = os.path.join(output_directory, f"{bucket_name}_sensitive_data_report.txt")
    
    with open(output_file_path, 'w') as file:
        for result in results:
            file.write(result + "\n")

    logging.info(f"Results written to {output_file_path}")

if __name__ == "__main__":
    main()
