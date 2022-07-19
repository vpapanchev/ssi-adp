# -*- coding: utf-8 -*-

import os
import logging
import logging.config

from flask import Flask

from ssi_access_decision_point import utils, constants
from ssi_access_decision_point.db import operations


def initialize_flask_app(name):
  # Do not use server configuration from this service config!
  service_config = utils.load_service_config()

  flask_app = Flask(name)
  configure_logging(service_config)

  operations.init_database()

  logging.info('Flask application initialized')
  return flask_app


def configure_logging(service_config):

  logging_config_path = os.getenv(constants.LOGGING_CNF_PATH_ENV_VAR,
                                  os.path.join(constants.PROJECT_DIRECTORY, 'config/logging.yml'))
  logging_config = utils.get_yaml_content(logging_config_path)
  logging_config['root']['level'] = service_config['logging']['level']
  logging.config.dictConfig(logging_config)
