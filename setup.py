from setuptools import setup

setup(
    name="pyntdsutil",
    version="1.0.0",
    author="mrdanielvelez",
    description="Dump NTDS.dit remotely with ntdsutil.exe via a modified version of atexec.py.",
    long_description="README.md",
    long_description_content_type="text/markdown",
    url="https://github.com/mrdanielvelez/pyntdsutil",
    license="MIT",
    install_requires=[
        "impacket"
    ],
    python_requires='>=3.6',
    entry_points={
    'console_scripts': [
        'pyntdsutil=pyntdsutil:main',
        ],
    }
)
