"""
Application settings and configuration
"""

import os
import dotenv

# Load environment variables
dotenv.load_dotenv()

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-4o"

# DVWA Configuration
DVWA_BASE_URL = os.getenv("DVWA_BASE_URL", "http://localhost:8000/dvwa")
DVWA_USERNAME = "admin"
DVWA_PASSWORD = "password"
DVWA_SECURITY_LEVEL = "low"

# Default payload generation settings
DEFAULT_NUM_PAYLOADS = 5
DEFAULT_NUM_DEFENSE_RULES = 3

NGROK_AUTHTOKEN = "3BsAFITReQh3QiJIsB40v8gPy7p_4mDoBhSHJuTopT1KysYgT"
NGROK_DOMAIN = "overrigged-savingly-nelle.ngrok-free.dev"