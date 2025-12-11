import os
from dotenv import load_dotenv
from huggingface_hub import HfApi

# Load biến môi trường từ file .env
load_dotenv()

# Khởi tạo API với token từ .env
api = HfApi(token=os.getenv("HF_TOKEN"))

# Upload folder
api.upload_folder(
    folder_path="C:/Users/nguye/Downloads/data_clean",
    repo_id="llm4waf/attack",
    repo_type="dataset",
)