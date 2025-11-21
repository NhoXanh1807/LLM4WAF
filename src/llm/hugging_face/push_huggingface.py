import os
from dotenv import load_dotenv
from huggingface_hub import HfApi

# Load biến môi trường từ file .env
load_dotenv()

# Khởi tạo API với token từ .env
api = HfApi(token=os.getenv("HF_TOKEN"))

# Upload folder
api.upload_folder(
    folder_path="C:/Users/nguye\Downloads/blue_data",
    repo_id="llm4waf/defend",
    repo_type="dataset",
)