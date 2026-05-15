from setuptools import setup, find_packages

setup(
    name="huginn-scanner",
    version="8.0.0",
    description="Advanced AI-Powered Security Scanner with Neural Networks and Quantum Fuzzing",
    author="Huginn Security Team",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.8.0",
        "beautifulsoup4>=4.11.0",
        "numpy>=1.21.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        'console_scripts': [
            'huginn-scan=app.tools.__main__:main',
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)