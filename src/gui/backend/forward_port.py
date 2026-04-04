import ngrok
from config.settings import NGROK_AUTHTOKEN, NGROK_DOMAIN
HOST_NAME = "127.0.0.1"
PORT = 5000

ngrok.set_auth_token(NGROK_AUTHTOKEN)
listener = ngrok.forward(addr=f"{HOST_NAME}:{PORT}", domain=NGROK_DOMAIN)
ADDRESS = listener.url()
print(f"NGROK: {HOST_NAME}:{PORT} -> {ADDRESS}")

input("Press Enter to stop the ngrok tunnel...")