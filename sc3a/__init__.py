import logging
from logging import handlers

formatter = logging.Formatter('%(asctime)s - %(name)s [%(levelname)s\t] %(message)s')

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(formatter)

file_handler = handlers.RotatingFileHandler('logs/out.log', maxBytes=100_000, backupCount=5)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

log = logging.getLogger(__name__)
log.addHandler(stream_handler)
log.addHandler(file_handler)
log.setLevel(logging.INFO)
