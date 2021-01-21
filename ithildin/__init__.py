import logging

from mythril.mythril.mythril_config import MythrilConfig

__version__ = '0.2.0'

formatter = logging.Formatter('[%(levelname)s\t] %(asctime)s - %(name)s %(message)s')

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(formatter)

log = logging.getLogger(__name__)
log.addHandler(stream_handler)
log.setLevel(logging.INFO)

# Ensure the mythril home directory '~/.mythril' is present and populated.
# This is an issue that arises when mythril is used as a library and tries to access ~/.mythril/signatures.db
# Related issue: https://github.com/metagon/ithildin/issues/1
MythrilConfig()
