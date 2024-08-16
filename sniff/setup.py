from setuptools import setup, find_packages

setup(
    name="sniff_admanvoids",  # Update the project name here
    version="0.1.4",
    author="Davey Mason",
    author_email="daveymason@outlook.com",
    description="A package for sniffing website information",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/daveymason/sniff",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "requests",
        "beautifulsoup4",
        "click",
        "whois",
        "cryptography"
    ],
    entry_points={
        'console_scripts': [
            'sniff=sniff.sniff:main',
        ],
    },
)
