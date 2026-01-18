"""Example usage of the Research Agent."""

from research_agent import ResearchAgent

def main():
    # Initialize the research agent
    agent = ResearchAgent(
        oval_xml_path=r"C:\Users\Yashvant\OneDrive\Documents\OVAL_WINDOWS.xml",
        ollama_model="llama3.2",  # Change to your preferred model
        # nvd_api_key="your-nvd-api-key",  # Optional
        # github_token="your-github-token"  # Optional
    )
    
    # Example 1: Research a CVE with additional vendor URL
    print("Example 1: Researching CVE-2025-5591")
    output1 = agent.research_cve(
        cve_id="CVE-2025-5591",
        additional_urls=[
            "https://www.themissinglink.com.au/security-advisories/cve-2025-5591"
        ]
    )
    agent.save_output(output1, "outputs/CVE-2025-5591_example.md")
    
    # Example 2: Research another CVE
    print("\nExample 2: Researching CVE-2026-21445")
    output2 = agent.research_cve(
        cve_id="CVE-2026-21445",
        additional_urls=[
            "https://github.com/langflow-ai/langflow/security/advisories/GHSA-c5cp-vx83-jhqx"
        ]
    )
    agent.save_output(output2, "outputs/CVE-2026-21445_example.md")
    
    print("\nExamples complete! Check the outputs/ directory for results.")

if __name__ == '__main__':
    main()
