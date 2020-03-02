import setuptools

setuptools.setup(
    name="fabricauthenticator",  # Replace with your own username
    version="0.0.1",
    description="Fabric Authenticator for Jupyterhub",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
