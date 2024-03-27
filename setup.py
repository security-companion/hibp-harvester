from setuptools import setup, find_packages

setup(
    name="hibp-harvester",
    version="1.0.4",
    author="Joachim Mammele",
    url="https://github.com/security-companion/hibp-harvester",
    description="A python tool to harvest haveibeenpwned.com via domain search",
    long_description=open('README.md', 'r').read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=["click", "requests"],
    entry_points={"console_scripts": ["hibp-harvester = src.hibp_harvester:main"]},
)
