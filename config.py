"""
CryptoVote Configuration Module
Supports local development (SQLite, local secrets) and production (Amazon RDS, AWS SSM Parameter Store).
"""
import os
from dotenv import load_dotenv

# Load local .env if present
load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))
default_sqlite_url = f"sqlite:///{os.path.join(basedir, 'cryptovote.db').replace(os.sep, '/')}"

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cryptovote-super-secret-key-2026')
    ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY', 'admin_secret_cryptovote_lab')

    # Database: Defaults to local SQLite, easily overridden by RDS MySQL connection string
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', default_sqlite_url)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # AWS Settings
    AWS_REGION = os.environ.get('AWS_REGION', 'ap-south-1')
    S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'cryptovote-results-lab')
    USE_PARAMETER_STORE = os.environ.get('USE_PARAMETER_STORE', 'False').lower() in ('true', '1', 'yes')
    PARAMETER_STORE_PREFIX = os.environ.get('PARAMETER_STORE_PREFIX', '/cryptovote/')

    @classmethod
    def load_from_parameter_store(cls):
        """
        Loads configuration and secrets directly from AWS Systems Manager Parameter Store.
        Called in production EC2 environment where IAM Role provides access.
        """
        if not cls.USE_PARAMETER_STORE:
            return

        try:
            import boto3
            ssm = boto3.client('ssm', region_name=cls.AWS_REGION)
            print(f"[*] Fetching parameters from SSM under {cls.PARAMETER_STORE_PREFIX}...")

            response = ssm.get_parameters_by_path(
                Path=cls.PARAMETER_STORE_PREFIX,
                Recursive=True,
                WithDecryption=True
            )

            for param in response.get('Parameters', []):
                name = param['Name'].replace(cls.PARAMETER_STORE_PREFIX, '').upper()
                value = param['Value']
                if name == 'DATABASE_URL' or name == 'DB_URL':
                    cls.SQLALCHEMY_DATABASE_URI = value
                elif name == 'ADMIN_SECRET':
                    cls.ADMIN_SECRET_KEY = value
                elif name == 'S3_BUCKET':
                    cls.S3_BUCKET_NAME = value
                print(f"[+] Loaded parameter: {name}")

        except Exception as e:
            print(f"[!] Warning: Could not load from Parameter Store: {e}")
