# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import logging
import logging.handlers
import errno

from faraday_agent_dispatcher import config

from syslog_rfc5424_formatter import RFC5424Formatter


def log_file():
    return os.path.expanduser(os.path.join(config.LOGS_PATH, "faraday-dispatcher.log"))


MAX_LOG_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_LOG_FILE_BACKUP_COUNT = 5
ROOT_LOGGER = "faraday_agent_dispatcher"
LOGGING_HANDLERS = []
LVL_SETTABLE_HANDLERS = []


def setup_logging():
    logger = logging.getLogger(ROOT_LOGGER)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    # if config.use_rfc5424_formatter:
    if config.USE_RFC:
        formatter = RFC5424Formatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s {%(threadName)s} "
            "[%(filename)s:%(lineno)s - %(funcName)s()]  %(message)s"
        )
    setup_console_logging(formatter)
    setup_file_logging(formatter)


def setup_console_logging(formatter):
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(config.LOGGING_LEVEL)
    console_handler.name = "CONSOLE_HANDLER"
    add_handler(console_handler)
    LVL_SETTABLE_HANDLERS.append(console_handler)


def setup_file_logging(formatter):
    create_logging_path()
    file_handler = logging.handlers.RotatingFileHandler(
        log_file(),
        maxBytes=MAX_LOG_FILE_SIZE,
        backupCount=MAX_LOG_FILE_BACKUP_COUNT,
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    file_handler.name = "FILE_HANDLER"
    add_handler(file_handler)


def add_handler(handler):
    logger = logging.getLogger(ROOT_LOGGER)
    for hldr in logger.handlers:
        if hldr.name == handler.name:
            logger.removeHandler(hldr)
    logger.addHandler(handler)
    LOGGING_HANDLERS.append(handler)


def get_logger(obj=None):
    """Creates a logger named by a string or an object's class name.
    Allowing logger to additionally accept strings as names
    for non-class loggings."""
    if obj is None:
        logger = logging.getLogger(ROOT_LOGGER)
        logger.setLevel(config.LOGGING_LEVEL)
    elif isinstance(obj, str):
        if obj != ROOT_LOGGER:
            logger = logging.getLogger(f"{ROOT_LOGGER}.{obj}")
        else:
            logger = logging.getLogger(obj)
    else:
        cls_name = obj.__class__.__name__
        logger = logging.getLogger(f"{ROOT_LOGGER}.{cls_name}")
    return logger


def set_logging_level(level):
    config.LOGGING_LEVEL = level
    for handler in LVL_SETTABLE_HANDLERS:
        handler.setLevel(level)


def create_logging_path():
    try:
        os.makedirs(os.path.dirname(log_file()))
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def reset_logger(logger_folder=None):
    if logger_folder is not None:
        config.LOGS_PATH = logger_folder
    setup_logging()


def get_level(loglevel: str):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: %s" % loglevel)
    return numeric_level
