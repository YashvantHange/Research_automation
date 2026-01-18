"""Check or setup Ollama for the research system."""

import sys
import argparse
import subprocess


def check_ollama() -> int:
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
        return 1

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
        return 1

    # Check 3: Test a simple query
    print("\n3. Testing Ollama with a simple query...")
    try:
        response = ollama.chat(
            model=model_list[0]['name'] if model_list else 'llama3.2',
            messages=[{'role': 'user', 'content': 'Say \"OK\" if you can read this.'}],
            options={'timeout': 5}
        )
        result = response['message']['content'].strip()
        print("   [OK] Ollama is responding correctly")
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
    return 0


def setup_ollama() -> int:
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

        print("[OK] Ollama service is running")
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
                messages=[{'role': 'user', 'content': 'Say \"OK\"'}],
                options={'timeout': 10}
            )
            result = response['message']['content'].strip()
            print("[OK] Ollama is working correctly!")
            print(f"[OK] Test response: {result[:50]}")
        except Exception as e:
            print(f"[WARNING] Test query failed: {e}")
            print("[INFO] Service is running but may need a model")

        print("\n" + "=" * 60)
        print("Ollama Setup Complete!")
        print("=" * 60)
        print(f"\nDefault model: {default_model}")
        print("Ollama is ready to use with the research system.")
        return 0

    except Exception as e:
        print(f"[ERROR] Cannot connect to Ollama: {e}")
        print("\nTo start Ollama:")
        print("1. Find ollama.exe on your system")
        print("2. Run: ollama serve")
        print("3. Or start Ollama from Start Menu")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Check or setup Ollama")
    parser.add_argument("--setup", action="store_true", help="Install/pull model and test Ollama")
    args = parser.parse_args()

    if args.setup:
        return setup_ollama()
    return check_ollama()


if __name__ == "__main__":
    raise SystemExit(main())
