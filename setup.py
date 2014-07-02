from setuptools import setup
import os


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()


version = "1.0b3"


setup(
    version=version,
    description="A plugin for ploy providing support for OpenVZ containers.",
    long_description=README + "\n\n",
    name="ploy_openvz",
    author='Florian Schulze',
    author_email='florian.schulze@gmx.net',
    license="BSD 3-Clause License",
    url='http://github.com/ployground/ploy_openvz',
    include_package_data=True,
    zip_safe=False,
    packages=['ploy_openvz'],
    install_requires=[
        'setuptools',
        'ploy >= 1.0rc9',
        'lazy'],
    entry_points="""
        [ploy.plugins]
        vz = ploy_openvz:plugin
    """)
