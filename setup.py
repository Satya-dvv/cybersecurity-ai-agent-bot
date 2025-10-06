from setuptools import setup, find_packages

setup(
    name="cybersecurity-ai-agent-bot",
    version="0.1.0",
    description="AI-powered cybersecurity assistant for CVE info, domain scanning, Q&A, and docs analysis",
    author="Satya Jagannadh",
    packages=find_packages(exclude=("tests", "docs")),
    include_package_data=True,
    install_requires=[
        "python-dotenv>=1.0.1",
        "requests>=2.32.0",
        "pydantic>=2.8.2",
        "loguru>=0.7.2",
        "httpx>=0.27.0",
        "rich>=13.7.1",
        "openai>=1.40.0",
        "click>=8.1.7",
    ],
    python_requires=">=3.8",
)
