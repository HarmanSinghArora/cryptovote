"""
AWS Lambda Function: close_election
Triggered by election administrators or EventBridge to securely close an election.

Workflow:
1. Retrieves /cryptovote/admin_secret from AWS Systems Manager Parameter Store with decryption.
2. Calls the Flask backend's POST /admin/close endpoint.
3. The Flask backend verifies the admin secret, tallies results, verifies the hash chain,
   and automatically uploads results.json and chain.json to Amazon S3.
4. Returns the election closure summary and S3 upload confirmation.
"""

import os
import json
import urllib.request
import urllib.error
import boto3

def lambda_handler(event, context):
    region = os.environ.get('AWS_REGION', 'ap-south-1')
    backend_url = os.environ.get('BACKEND_URL', 'http://127.0.0.1:5000').rstrip('/')
    admin_secret_param = os.environ.get('ADMIN_SECRET_PARAM', '/cryptovote/admin_secret')

    print(f"[*] Starting close_election Lambda execution in region: {region}")
    print(f"[*] Target Backend URL: {backend_url}")

    # 1. Retrieve Admin Secret from Systems Manager Parameter Store
    try:
        ssm = boto3.client('ssm', region_name=region)
        param_response = ssm.get_parameter(
            Name=admin_secret_param,
            WithDecryption=True
        )
        admin_secret = param_response['Parameter']['Value']
        print("[+] Successfully retrieved admin secret from Parameter Store.")
    except Exception as e:
        error_msg = f"Failed to retrieve admin secret from Parameter Store: {str(e)}"
        print(f"[!] {error_msg}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': error_msg})
        }

    # 2. Invoke POST /admin/close on the Backend
    endpoint = f"{backend_url}/admin/close"
    payload = json.dumps({'admin_secret': admin_secret}).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'X-Admin-Secret': admin_secret
    }

    req = urllib.request.Request(endpoint, data=payload, headers=headers, method='POST')

    try:
        print(f"[*] Sending election close request to {endpoint}...")
        with urllib.request.urlopen(req, timeout=20) as response:
            status_code = response.getcode()
            response_body = response.read().decode('utf-8')
            response_json = json.loads(response_body)

            print(f"[+] Election successfully closed! Backend returned HTTP {status_code}.")
            print(f"[+] S3 Status: {response_json.get('s3_status')}")

            return {
                'statusCode': status_code,
                'body': json.dumps({
                    'message': 'Election closed successfully via Lambda trigger',
                    'backend_response': response_json
                })
            }

    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8') if e.fp else str(e)
        print(f"[!] Backend returned HTTP {e.code}: {err_body}")
        return {
            'statusCode': e.code,
            'body': json.dumps({
                'error': f"Backend error during election close: {e.reason}",
                'details': err_body
            })
        }
    except Exception as e:
        print(f"[!] Connection error contacting backend: {str(e)}")
        return {
            'statusCode': 502,
            'body': json.dumps({
                'error': f"Could not connect to backend at {endpoint}: {str(e)}"
            })
        }
