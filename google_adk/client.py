import os
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables from .env file
load_dotenv()

def configure_genai():
    # Try GEMINI_API_KEY first (from .env), then fall back to GOOGLE_API_KEY
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    
    # Strip whitespace from API key
    if api_key:
        api_key = api_key.strip()
    
    if not api_key:
        raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY environment variable is missing")
    
    genai.configure(api_key=api_key)

def get_model(json_mode=False):
    """Returns an available Gemini model for generation."""
    configure_genai()
    
    generation_config = {
        "temperature": 0.3,
        "max_output_tokens": 2048,
    }
    
    if json_mode:
        generation_config["response_mime_type"] = "application/json"

    # Use the latest available Gemini model
    model_name = "gemini-2.5-flash"
    
    return genai.GenerativeModel(
        model_name=model_name,
        generation_config=generation_config
    )