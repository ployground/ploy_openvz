from setuptools import setup
import os


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()


version = "1.0b2"


setup(
    version=version,
    description="A plugin for mr.awsome providing support for OpenVZ containers.",
    long_description=README + "\n\n",
    name="mr.awsome.openvz",
    author='Florian Schulze',
    author_email='florian.schulze@gmx.net',
    url='http://github.com/fschulze/mr.awsome.openvz',
    include_package_data=True,
    zip_safe=False,
    packages=['mr'],
    namespace_packages=['mr'],
    install_requires=[
        'setuptools',
        'mr.awsome >= 1.0rc2',
        'lazy'],
    entry_points="""
        [mr.awsome.plugins]
        vz = mr.awsome_openvz:plugin
    """)
