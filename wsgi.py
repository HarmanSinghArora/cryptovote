"""
WSGI Entry Point for Production Deployment on AWS EC2
Used by Gunicorn to serve the CryptoVote Flask application.
"""
from app import create_app
from config import Config

# Attempt to load configuration from AWS Systems Manager Parameter Store if running in AWS
Config.load_from_parameter_store()

app = create_app(Config)

if __name__ == "__main__":
    app.run()
