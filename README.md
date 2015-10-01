# apple-mail-uploader
Imports Apple Mail to Gmail

## Requirements:
   * Python 2.7
   * Google Python API (https://pypi.python.org/pypi/google-api-python-client/)
   * Google Console API Client ID and Secret
   
## Setup
1.  Extract Google Python API and run:  python setup.py install --user
2.  Modify credentials.py and set values for CLIENT_ID and CLIENT_SECRET

## Usage

There are three command line switches:

--help   : provides usage message<br />
--reauth : forces reauthentication<br />
--redoall: forces reimporting of all messages in MBOX

