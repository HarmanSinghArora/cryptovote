"""
Database Migration Script for Amazon RDS MySQL
Executes db/schema.sql directly on the Amazon RDS MySQL instance and seeds initial candidates.
Can be executed from EC2 (within the VPC) or directly once network connectivity is established.
"""

import os
import sys
import boto3
import pymysql

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def migrate(host=None, user=None, password=None, db_name="cryptovote_db", port=3306):
    ssm = boto3.client('ssm', region_name='ap-south-1')
    rds = boto3.client('rds', region_name='ap-south-1')

    # If host not provided, attempt to discover from RDS instance
    if not host:
        print("[*] Discovering RDS endpoint for 'cryptovote-mysql'...")
        try:
            dbs = rds.describe_db_instances(DBInstanceIdentifier='cryptovote-mysql')
            inst = dbs['DBInstances'][0]
            endpoint = inst.get('Endpoint', {})
            host = endpoint.get('Address')
            port = endpoint.get('Port', 3306)
            status = inst.get('DBInstanceStatus')
            print(f"[+] Found DB instance! Status: {status}, Host: {host}")
            if status != 'available':
                print(f"[!] Warning: RDS is still '{status}'. It must be 'available' before connecting.")
                return False
        except Exception as e:
            print(f"[!] Could not auto-detect RDS endpoint: {e}")

    # Read credentials from Parameter Store if not explicitly passed
    if not user:
        try:
            param = ssm.get_parameter(Name='/cryptovote/db_user')
            user = param['Parameter']['Value']
        except Exception:
            user = 'admin'

    if not password:
        try:
            param = ssm.get_parameter(Name='/cryptovote/db_password', WithDecryption=True)
            password = param['Parameter']['Value']
        except Exception:
            password = 'CryptoVoteDBPass2026!'

    print(f"\n[*] Connecting to MySQL at {host}:{port} as user '{user}'...")
    try:
        conn = pymysql.connect(
            host=host,
            user=user,
            password=password,
            port=int(port),
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        print("[+] MySQL connection established!")

        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        with open(schema_path, 'r', encoding='utf-8') as f:
            sql_script = f.read()

        with conn.cursor() as cursor:
            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}` DEFAULT CHARACTER SET utf8mb4;")
            cursor.execute(f"USE `{db_name}`;")
            print(f"[+] Using database `{db_name}`.")

            # Split statements by semicolon
            statements = [s.strip() for s in sql_script.split(';') if s.strip()]
            for stmt in statements:
                # Remove SQL comment lines
                clean_lines = [l for l in stmt.splitlines() if not l.strip().startswith('--')]
                clean_stmt = '\n'.join(clean_lines).strip()
                if clean_stmt:
                    cursor.execute(clean_stmt)
            
            conn.commit()
            print("[+] All schema tables created and initial candidates seeded successfully!")

            cursor.execute("SHOW TABLES;")
            tables = [list(row.values())[0] for row in cursor.fetchall()]
            print(f"[+] Verified RDS Tables: {tables}")

            cursor.execute("SELECT id, name, party FROM candidates;")
            candidates = cursor.fetchall()
            print("[+] Active Candidates in RDS:")
            for c in candidates:
                print(f"  - [{c['id']}] {c['name']} ({c['party']})")

        conn.close()

        # Update /cryptovote/database_url in Parameter Store
        db_url = f"mysql+pymysql://{user}:{password}@{host}:{port}/{db_name}"
        ssm.put_parameter(
            Name='/cryptovote/database_url',
            Value=db_url,
            Type='SecureString',
            Overwrite=True
        )
        print(f"[+] Stored full DATABASE_URL in Parameter Store (/cryptovote/database_url)!")
        return True

    except Exception as e:
        print(f"[!] Migration failed: {e}")
        return False

if __name__ == '__main__':
    host_arg = sys.argv[1] if len(sys.argv) > 1 else None
    migrate(host=host_arg)
