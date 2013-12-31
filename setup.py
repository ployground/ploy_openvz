from setuptools import setup

version = "0.1"

setup(
    version=version,
    description="A plugin for mr.awsome providing support for OpenVZ containers.",
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
        'Fabric >= 1.3.0',
        'lazy'
    ],
    entry_points="""
      [mr.awsome.providerplugins]
      vz = mr.awsome.openvz:providerplugin
    """)