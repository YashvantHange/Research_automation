"""Pull the required Ollama model for the research system."""

import ollama
import sys

print("=" * 60)
print("Pulling Ollama Model")
print("=" * 60)
print()

model_name = "llama3.2"
print(f"Pulling model: {model_name}")
print("This may take a few minutes depending on your internet speed...")
print()

try:
    # Pull the model
    result = ollama.pull(model_name)
    print(f"[OK] Model '{model_name}' pulled successfully!")
    print()
    
    # Verify it's available
    models = ollama.list()
    model_list = models.get('models', [])
    if any(m.get('name', '').startswith(model_name) for m in model_list):
        print(f"[OK] Model '{model_name}' is now available")
        print()
        print("Ollama is ready to use!")
    else:
        print(f"[WARNING] Model '{model_name}' may not be fully ready")
        
except Exception as e:
    print(f"[ERROR] Failed to pull model: {e}")
    print()
    print("You can try manually:")
    print(f"  ollama pull {model_name}")
    sys.exit(1)

print()
print("=" * 60)
print("Setup Complete!")
print("=" * 60)
