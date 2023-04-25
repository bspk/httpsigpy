import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="httpsigpy",
    version="0.0.8",
    author="Justin Richer",
    author_email="python@justin.richer.org",
    description="HTTP Message Signatures",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bspkio/httpsigpy",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)