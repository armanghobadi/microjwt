from setuptools import setup, find_packages

setup(
    name="microjwt",
    version="0.1.0",
    packages=find_packages(),
    description="A lightweight JWT implementation with HMAC SHA-256 signing",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    author="Arman Ghobadi",
    author_email="arman.ghobadi.ag@gmail.com",
    url="https://github.com/armanghobadi/microjwt",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    install_requires=[],
    tests_require=["pytest"],
    python_requires=">=3.7",
)
