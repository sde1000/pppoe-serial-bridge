#!/usr/bin/env python3

from setuptools import setup  # type: ignore
from Cython.Build import cythonize  # type: ignore

setup(name='pppoe',
      version='0.1',
      description='PPPoE to serial PPP bridge',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: GNU General Public License '
          'v3 or later (GPLv3+)',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Topic :: System :: Networking',
          'Intended Audience :: System Administrators',
          'Operating System :: POSIX :: Linux',
          'Environment :: Console',
      ],
      keywords='pppoe',
      url='https://github.com/sde1000/pppoe-serial-bridge',
      author='Stephen Early',
      author_email='steve@assorted.org.uk',
      license='GPL3+',
      license_files=['LICENSE'],
      packages=['pppoe'],
      scripts=['pppoe-serial-bridge.py'],
      install_requires=[
          'netifaces',
          'pyserial',
      ],
      include_package_data=True,
      ext_modules=cythonize("pppoe/*.pyx",
                            compiler_directives={'language_level': '3'}),
      zip_safe=False)
