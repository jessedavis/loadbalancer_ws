# extra logging, should probably be done another way

LOGGING_INITIATED = False

import logging, logging.handlers
from django.conf import settings

def init_logging():
    logger = logging.getLogger()
    level = logging.INFO
    #level = logging.WARN
    logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter("%(asctime)s - %(name)s - jdavis - %(levelname)s -     %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

if not LOGGING_INITIATED:
    LOGGING_INITIATED = True
    init_logging()
