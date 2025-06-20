from dotenv import load_dotenv
import os

load_dotenv()  # loads from .env

class Config:
    MONGO_URI = os.getenv("MONGO_URI")
    SECRET_KEY = os.getenv("SECRET_KEY")
