"""Setup and configure Ollama for the research system."""

import sys
import subprocess

print("=" * 60)
print("Setting Up Ollama")
print("=" * 60)
print()

# Check if Ollama Python package is available
try:
    import ollama
    print("[OK] Ollama Python package is installed")
except ImportError:
    print("[ERROR] Ollama Python package not installed")
    print("Installing...")
    subprocess.run([sys.executable, "-m", "pip", "install", "ollama"], check=True)
    import ollama
    print("[OK] Ollama Python package installed")

# Check Ollama service
print("\n[INFO] Checking Ollama service...")
try:
    client = ollama.Client()
    models_response = client.list()
    
    # Extract model names
    models = models_response.get('models', [])
    model_names = []
    for model in models:
        name = model.get('name', '') or str(model)
        model_names.append(name)
    
    print(f"[OK] Ollama service is running")
    print(f"[OK] Found {len(model_names)} model(s)")
    
    if model_names:
        print("\nAvailable models:")
        for name in model_names:
            print(f"  - {name}")
    else:
        print("[WARNING] No models found")
    
    # Check if default model exists
    default_model = "llama3.2"
    has_default = any(default_model in name.lower() for name in model_names)
    
    if not has_default:
        print(f"\n[INFO] Default model '{default_model}' not found")
        print(f"[INFO] Pulling {default_model}...")
        try:
            print("This may take a few minutes...")
            client.pull(default_model)
            print(f"[OK] Successfully pulled {default_model}")
        except Exception as e:
            print(f"[WARNING] Could not pull {default_model}: {e}")
            if model_names:
                print(f"[INFO] Using first available model: {model_names[0]}")
                default_model = model_names[0]
    else:
        print(f"[OK] Default model '{default_model}' is available")
    
    # Test Ollama with a simple query
    print("\n[INFO] Testing Ollama...")
    test_model = default_model if has_default else (model_names[0] if model_names else default_model)
    try:
        response = client.chat(
            model=test_model,
            messages=[{'role': 'user', 'content': 'Say "OK"'}],
            options={'timeout': 10}
        )
        result = response['message']['content'].strip()
        print(f"[OK] Ollama is working correctly!")
        print(f"[OK] Test response: {result[:50]}")
    except Exception as e:
        print(f"[WARNING] Test query failed: {e}")
        print("[INFO] Service is running but may need a model")
    
    print("\n" + "=" * 60)
    print("Ollama Setup Complete!")
    print("=" * 60)
    print(f"\nDefault model: {default_model}")
    print("Ollama is ready to use with the research system.")
    
except Exception as e:
    print(f"[ERROR] Cannot connect to Ollama: {e}")
    print("\nTo start Ollama:")
    print("1. Find ollama.exe on your system")
    print("2. Run: ollama serve")
    print("3. Or start Ollama from Start Menu")
    sys.exit(1)
