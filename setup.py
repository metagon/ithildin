import pathlib
from setuptools import find_packages, setup

VERSION = '0.2.2'
CURRENT_DIR = pathlib.Path(__file__).parent
README = (CURRENT_DIR / 'README.md').read_text()
PYTHON_REQUIREMENT = '>=3.6.0'

REQUIREMENTS = [
    "Jinja2==2.11.2",
    "mythril==0.22.14",
    "SQLAlchemy==1.3.22"
]

setup(
    name='ithildin',
    version=VERSION,
    description='Semantic analyzer of EVM bytecode based on Mythril',
    long_description=README,
    long_description_content_type='text/markdown',
    url='https://github.com/metagon/ithildin',
    author='Philippos Gorgoris',
    author_email='philippos@gorgoris.com',
    license='MIT',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8'
    ],
    packages=find_packages(exclude=('scripts')),
    include_package_data=True,
    install_requires=REQUIREMENTS,
    python_requires=PYTHON_REQUIREMENT,
    entry_points={'console_scripts': ['ithil=ithildin.__main__:main']}
)
