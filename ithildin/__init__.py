import logging
from logging import handlers

from .setup import setup

formatter = logging.Formatter('%(asctime)s - %(name)s [%(levelname)s\t] %(message)s')

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(formatter)

log = logging.getLogger(__name__)
log.addHandler(stream_handler)
log.setLevel(logging.INFO)

# Execute setup script
setup()
