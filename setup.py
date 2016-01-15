#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='apple-mail-uploader',
      version='1.0.3',
      description='Apple Mail|GMail Uploader',
      author='Doug Campbell',
      author_email='wdouglascampbell@hotmail.com',
      url='https://github.com/wdouglascampbell/apple-mail-uploader',
      packages=find_packages(),
      license='GPLv3',
      install_requires=[
          'biplist',
          'google-api-python-client',
      ],
     )
