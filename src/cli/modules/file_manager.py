
from modules.classes import OutputType, File

import os
import json
OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../outputs"))
INDEX_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../outputs_index.json"))
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _ensure_index_file() -> None:
    if not os.path.exists(INDEX_FILE):
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2)


def _load_index() -> dict:
    _ensure_index_file()
    with open(INDEX_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _save_index(index_data: dict) -> None:
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2)

def save_file(output_type: OutputType, content) -> File:
    index_data = _load_index()
    id = 0
    if output_type.value not in index_data:
        index_data[output_type.value] = []
    else:
        existing_ids = [int(file['id']) for file in index_data[output_type.value]]
        while id in existing_ids:
            id += 1
    file_name = f"{output_type.value}{id}"
    file_path = os.path.join(OUTPUT_DIR, f"{file_name}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2)
    index_data[output_type.value].append({"output_type": output_type.value, "id": id, "name": file_name, "path": file_path})
    _save_index(index_data)
    return File(output_type=output_type, id=id, path=file_path)

def list_files() -> list[File]:
    results = []
    index_data = _load_index()
    for output_type, files in index_data.items():
        for file in files:
            results.append(File(
                output_type=OutputType(output_type),
                id=int(file["id"]),
                path=file["path"]
            ))
    return results

def remove_file(file_id: str) -> bool:
    index_data = _load_index()
    for output_type, files in index_data.items():
        for i, file in enumerate(files):
            if file["output_type"] + str(file["id"]) == file_id:
                file_path = file["path"]
                if os.path.exists(file_path):
                    os.remove(file_path)
                del index_data[output_type][i]
                _save_index(index_data)
                return True
    return False

def read_file(file_name: str) -> str | None:
    index_data = _load_index()
    for output_type, files in index_data.items():
        for file in files:
            if file['name'] == file_name:
                file_path = file["path"]
                if os.path.exists(file_path):
                    with open(file_path, "r", encoding="utf-8") as f:
                        return f.read()
    return None