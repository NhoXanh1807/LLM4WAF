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
DVWA_BASE_URL = "http://llmshield.akng.io.vn"
DVWA_USERNAME = "admin"
DVWA_PASSWORD = "password"
DVWA_SECURITY_LEVEL = "low"

# Default payload generation settings
DEFAULT_NUM_PAYLOADS = 5
DEFAULT_NUM_DEFENSE_RULES = 3

HF_ACCESS_TOKEN = os.getenv("HF_ACCESS_TOKEN")

