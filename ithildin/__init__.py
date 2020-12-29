import logging
import os

__version__ = '0.1.0'

formatter = logging.Formatter('[%(levelname)s\t] %(asctime)s - %(name)s %(message)s')

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(formatter)

log = logging.getLogger(__name__)
log.addHandler(stream_handler)
log.setLevel(logging.INFO)

# Ensure the mythril home directory '~/.mythril' is present.
# This is an issue that arises when mythril is used as a library and tries to access ~/.mythril/signatures.db
# Related issue: https://github.com/metagon/ithildin/issues/1
myth_home = os.path.join(os.path.expanduser('~'), '.mythril')
if not os.path.exists(myth_home):
    log.info('Creating mythril home directory ~/.mythril')
    os.mkdir(myth_home)
