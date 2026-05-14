import re

import httpx


BASE_URL = "http://localhost:8000"


def main() -> None:
    client = httpx.Client(follow_redirects=True, timeout=30.0)
    setup_url = f"{BASE_URL}/setup.php"
    response = client.get(setup_url)
    token_match = re.search(r'user_token.*?value=["\']([a-f0-9]+)', response.text, re.I)
    if not token_match:
        raise SystemExit("Could not extract user_token from DVWA setup page. Make sure docker compose is up and the app is healthy.")

    token = token_match.group(1)
    result = client.post(
        setup_url,
        data={"create_db": "Create / Reset Database", "user_token": token},
        follow_redirects=False,
    )
    location = result.headers.get("location", "")
    if result.status_code in {301, 302} or "created" in result.text.lower() or "successfully" in result.text.lower():
        print("DVWA database setup request completed.")
        print(f"HTTP status: {result.status_code} | Location: {location}")
        return

    raise SystemExit(f"DVWA database setup may have failed. HTTP status={result.status_code} | Location={location}")


if __name__ == "__main__":
    main()