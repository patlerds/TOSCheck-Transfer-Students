# In /home/royans/c/wkb/flask/wkb.wsgi
import sys
import logging 

logging.basicConfig(stream=sys.stderr)

# This adds your app's directory to the path so it can be imported.
# The virtual environment is handled by Apache.
sys.path.insert(0, '/home/nish/web/TOSCheck')

from app import app as application
#Version of the app: 1.0.1.22
#Date: 2026-02-14 