from setuptools import setup, find_packages

setup(
    name="auditaiflow",
    version="1.0.0",
    description="Multi-agent enterprise auditing system built on Google's Agent Development Kit",
    author="AuditAIFlow Team",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "google-genai>=0.1.0",
        "python-dotenv>=0.19.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
