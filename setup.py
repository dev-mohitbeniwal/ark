from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ark",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A secure local ark for storing sensitive information",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ark",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
    install_requires=[
        "click>=7.1.2",
        "cryptography>=3.4.7",
        "pyperclip>=1.8.2",
    ],
    entry_points={
        "console_scripts": [
            "ark=local_vault.cli:cli",
        ],
    },
)