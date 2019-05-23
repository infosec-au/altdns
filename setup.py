import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="py-altdns",
    version="1.0.0",
    author="Shubham Shah",
    author_email="sshah@assetnote.io",
    description="Generates permutations, alterations and mutations of subdomains and then resolves them.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/infosec-au/altdns",
    packages=setuptools.find_packages(),
    entry_points={
        "console_scripts": [
            "altdns=altdns.__main__:main",
        ]
    },
    install_requires=["tldextract","argparse","termcolor","dnspython"],
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Security"
    ],
)