import setuptools

VERSION = "0.0.3.0"

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="fabricauthenticator",
    version=VERSION,
    author="Erica Fu",
    author_email="ericafu@renci.org",
    description="Fabric Authenticator for Jupyterhub",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fabric-testbed/fabricauthenticator",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
