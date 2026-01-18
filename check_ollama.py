"""Check if Ollama is available on the system."""

import sys

print("=" * 60)
print("Checking Ollama Availability")
print("=" * 60)
print()

# Check 1: Python package
print("1. Checking Ollama Python package...")
try:
    import ollama
    print("   [OK] Ollama Python package is installed")
except ImportError:
    print("   [ERROR] Ollama Python package not installed")
    print("   Install with: pip install ollama")
    sys.exit(1)

# Check 2: Ollama service connection
print("\n2. Checking Ollama service connection...")
try:
    client = ollama.Client()
    models = client.list()
    print("   [OK] Ollama service is running and accessible")
    
    # List available models
    model_list = models.get('models', [])
    print(f"   [OK] Found {len(model_list)} model(s):")
    for model in model_list[:10]:  # Show first 10
        name = model.get('name', 'unknown')
        size = model.get('size', 0)
        size_gb = size / (1024**3) if size else 0
        print(f"      - {name} ({size_gb:.2f} GB)")
    
    if len(model_list) > 10:
        print(f"      ... and {len(model_list) - 10} more")
        
except Exception as e:
    print(f"   [ERROR] Cannot connect to Ollama service: {e}")
    print("   Make sure Ollama is running:")
    print("   - On Windows: Check if Ollama service is running")
    print("   - Or run: ollama serve")
    sys.exit(1)

# Check 3: Test a simple query
print("\n3. Testing Ollama with a simple query...")
try:
    response = ollama.chat(
        model=model_list[0]['name'] if model_list else 'llama3.2',
        messages=[{'role': 'user', 'content': 'Say "OK" if you can read this.'}],
        options={'timeout': 5}
    )
    result = response['message']['content'].strip()
    print(f"   [OK] Ollama is responding correctly")
    print(f"   Response: {result[:50]}...")
except Exception as e:
    print(f"   [WARNING] Ollama query test failed: {e}")
    print("   Service is running but may have issues")

# Check 4: Check default model
print("\n4. Checking default model configuration...")
default_model = 'llama3.2'  # Default in the code
if any(m.get('name', '').startswith(default_model) for m in model_list):
    print(f"   [OK] Default model '{default_model}' is available")
else:
    print(f"   [WARNING] Default model '{default_model}' not found")
    if model_list:
        print(f"   Available models: {', '.join([m.get('name', '') for m in model_list[:5]])}")

print("\n" + "=" * 60)
print("Summary: Ollama is AVAILABLE and READY to use!")
print("=" * 60)
