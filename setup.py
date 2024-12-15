from setuptools import setup, find_packages

setup(
    name="microjwt",  
    description="A simple HMAC-based JWT implementation for MicroPython",
    author="Arman Ghobadi",  
    author_email="arman.ghobadi.ag@gmai.com",  
    url="https://github.com/armanghobadi/microjwt",  
    packages=find_packages(),  
    install_requires=[  
        "ubinascii",  
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',  
)
