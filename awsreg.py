import boto3
import re
import os
import logging
import pdfplumber
import csv
from io import BytesIO

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
    """Extract and return the text from a CSV content."""
    text = []
    try:
        decoded_content = BytesIO(file_content).getvalue().decode('utf-8')
    except UnicodeDecodeError:
        decoded_content = BytesIO(file_content).getvalue().decode('iso-8859-1')
    
    csv_reader = csv.reader(decoded_content.splitlines())
    for row in csv_reader:
        text.append(','.join(row))
    return '\n'.join(text)

def search_content(s3, bucket_name, regex_pattern):
    """Search for the given regex pattern in all files of the bucket."""
    results = []
    try:
        for file_key in list_s3_objects(s3, bucket_name):
            obj = s3.get_object(Bucket=bucket_name, Key=file_key)
            file_content = obj['Body'].read()
            file_type = obj.get('ContentType', 'application/octet-stream')  # Default to binary type if ContentType is not provided

            if 'text' in file_type or file_key.endswith('.txt'):
                try:
                    file_text = file_content.decode('utf-8')
                except UnicodeDecodeError:
                    file_text = file_content.decode('iso-8859-1')  # Try another encoding
            elif 'application/pdf' in file_type or file_key.endswith('.pdf'):
                file_text = extract_text_from_pdf(file_content)
            elif 'text/csv' in file_type or file_key.endswith('.csv'):
                file_text = extract_text_from_csv(file_content)
            else:
                logging.info(f"Skipped unsupported file type: {file_key}")
                continue

            matches = regex_pattern.findall(file_text)
            if matches:
                results.append(f"Found matches in {file_key}: {matches}")
            else:
                results.append(f"No matches found in {file_key}")
    except Exception as e:
        logging.error(f"An error occurred while processing files in {bucket_name}: {e}")
    return results

def main():
    s3 = create_s3_client()
    bucket_name = input("Enter the S3 bucket name: ")
    regex_pattern = re.compile(input("Enter the regex pattern to search for: "))

    results = search_content(s3, bucket_name, regex_pattern)
    for result in results:
        print(result)

if __name__ == "__main__":
    main()
