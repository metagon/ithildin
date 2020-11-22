import os
import logging

log = logging.getLogger(__name__)


def setup():
    # Ensure the mythril home directory '~/.mythril' is present.
    # This is an issue that arises when mythril is used as a library and tries to access ~/.mythril/signatures.db
    # Related issue: https://github.com/metagon/sc3a/issues/1
    myth_home = os.path.join(os.path.expanduser('~'), '.mythril')
    if not os.path.exists(myth_home):
        log.info('Creating mythril home directory ~/.mythril')
        os.mkdir(myth_home)
