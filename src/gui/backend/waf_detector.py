import subprocess

def detect_waf(domain: str) -> dict:
    """
    Detect the Web Application Firewall (WAF) protecting a given domain.

    Args:
        domain (str): The domain to be analyzed.

    Returns:
        dict: A dictionary containing detection result.
    """
    try:
        # Run wafw00f as a subprocess
        result = subprocess.run(
            ["wafw00f", domain],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Check for errors
        if result.returncode != 0:
            return {
                "status": "error",
                "message": f"wafw00f returned non-zero exit code: {result.returncode}",
                "stderr": result.stderr.strip(),
            }

        # Return detection result
        return {
            "status": "success",
            "domain": domain,
            "output": result.stdout.strip()
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "Detection timed out (30s limit)"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
