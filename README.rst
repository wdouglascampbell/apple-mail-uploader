Apple Mail|Gmail Uploader
=========================

Imports Apple Mail e-mails into GMail


Setup
-----
1. Extract files from archive
2. Change to folder containing extracted archive
3. Run the following command from the terminal prompt:

python setup.py install --user

4. Run the following command from the terminal prompt to process a mail migration:

./apple-mail-uploader.py


Usage
-----

There are three command line switches:

- --help : displays usage message
- --reauth : forces reauthentication
- --redoall: forces reimporting of all messages in MBOX

