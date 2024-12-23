from setuptools import setup, find_packages

setup(
    name="gpt-language-server",
    version="0.1.0",
    description="Add your description here",
    long_description=open("readme.md").read(),
    long_description_content_type="text/markdown",
    author="maliubiao",
    author_email="maliubiao@gmail.com",
    url="https://github.com/maliubiao/gpt-summary",
    packages=find_packages(),
    install_requires=[
        "flask[async]>=3.1.0",
        "google-generativeai>=0.8.3",
        "markdown>=3.7",
        "openai==0.28",
        "pip>=24.3.1",
        "tornado>=6.4.2",
        "tqdm>=4.67.1",
        "weasyprint>=63.1",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'gpt-lsp=gpt_lsp.__main__:main',
        ],
    },
)
