import logging

from .setup import setup

formatter = logging.Formatter('[%(levelname)s\t] %(asctime)s - %(name)s %(message)s')

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(formatter)

log = logging.getLogger(__name__)
log.addHandler(stream_handler)
log.setLevel(logging.INFO)

# Execute setup script
setup()
