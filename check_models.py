from groq import Groq
import os
from dotenv import load_dotenv
load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
models = client.models.list()
vision = [m.id for m in models.data if 'vision' in m.id.lower() or 'scout' in m.id.lower() or 'llama-4' in m.id.lower()]
print(vision)