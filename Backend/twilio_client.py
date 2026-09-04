import os
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID")

if not TWILIO_ACCOUNT_SID:
    raise RuntimeError("TWILIO_ACCOUNT_SID is missing from .env")

if not TWILIO_AUTH_TOKEN:
    raise RuntimeError("TWILIO_AUTH_TOKEN is missing from .env")

if not TWILIO_VERIFY_SERVICE_SID:
    raise RuntimeError("TWILIO_VERIFY_SERVICE_SID is missing from .env")

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)