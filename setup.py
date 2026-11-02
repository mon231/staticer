import setuptools
from pathlib import Path


CURRENT_FOLDER = Path(__file__).parent
README_PATH = CURRENT_FOLDER / 'README.md'


def main():
    setuptools.setup(
        name = "staticer",
        version = "1.0.0",
        author = "Ariel Tubul",
        description = "Embed dependencies in dynamic-executables",
        packages = setuptools.find_packages(),
        long_description = README_PATH.read_text(),
        url = "https://github.com/mon231/staticer/",
        long_description_content_type='text/markdown',
        entry_points = {'console_scripts': ['staticer=staticer.staticer:main']},
        python_requires = '>=3.9',
        install_requires = ['firstclass<0.3', 'pefile', 'pyelftools']
    )


if __name__ == '__main__':
    main()
