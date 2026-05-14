import os
import dotenv
dotenv.load_dotenv(os.path.abspath(os.path.join(os.path.dirname(__file__), ".env")))

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-5.4"
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")
CLAUDE_MODEL = "claude-sonnet-4-6"
LLMSHIELD_ENDPOINT = os.getenv("LLMSHIELD_ENDPOINT")
XSS_HARMNESS_VALIDATOR_ENDPOINT = os.getenv("XSS_HARMNESS_VALIDATOR_ENDPOINT")