from setuptools import setup, find_packages

setup(
    name='emailfy',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'dnspython>=2.5.0',
        'idna>=2.0.0'
    ],
)
