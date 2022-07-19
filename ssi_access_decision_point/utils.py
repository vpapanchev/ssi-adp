import sys
import os
import re
import logging
import asyncio
import random

from yaml import safe_load, YAMLError
from ssi_access_decision_point import constants
from rdflib import Graph


def load_component_configuration(component_name):
  if not re.fullmatch(constants.VALID_COMPONENT_NAME_REGEX, component_name):
    logging.error(constants.LOG_INVALID_COMP_NAME,
                  component_name, constants.VALID_COMPONENT_NAME_REGEX)
    return

  if component_name == 'server':
    # Exception for server config due to env variables (dirty fix)
    return get_server_configuration()

  service_config = load_service_config()
  if component_name not in service_config:
    logging.error(constants.LOG_CNF_COMPONENT_MISSING, component_name)
    return
  return service_config[component_name]


def load_service_config():
  def terminate_program_with_message(message):
    print(message)
    sys.exit(1)

  config_file_path = os.getenv(constants.CONFIG_FILE_PATH_ENV_VARIABLE,
                               os.path.join(constants.PROJECT_DIRECTORY, 'config/config.yml'))
  project_config = get_yaml_content(config_file_path, terminate_program_with_message)
  if constants.CONF_SERVICES_NAME not in project_config:
    logging.error(constants.LOG_CNF_NO_SERVICES)
    terminate_program_with_message(constants.LOG_CNF_NO_SERVICES)
  services_config = project_config[constants.CONF_SERVICES_NAME]
  if constants.SERVICE_NAME not in services_config:
    logging.error(constants.LOG_CNF_UNAVAIL_SERVICE)
    terminate_program_with_message(constants.LOG_CNF_UNAVAIL_SERVICE)
  return services_config[constants.SERVICE_NAME]


def get_yaml_content(file_path, callback_on_error=None):
  with open(os.path.join(file_path), 'r') as file:
    try:
      return safe_load(file)
    except YAMLError as error:
      error_msg = constants.LOG_YAML_PARSE_FAIL.format(file, error)
      if callback_on_error:
        callback_on_error(error_msg)
      logging.error(error_msg)


def get_server_configuration():
  server_local_config = load_service_config()['server']
  host = os.getenv('API_HOST', server_local_config['host'])
  port = os.getenv('API_PORT', server_local_config['port'])
  debug = os.getenv('API_DEBUG', server_local_config['debug'])

  return {
    'host': host,
    'port': port,
    'debug': debug
  }


def get_or_create_eventloop():
  try:
    return asyncio.get_event_loop()
  except RuntimeError as ex:
    if "There is no current event loop in thread" in str(ex):
      loop = asyncio.new_event_loop()
      asyncio.set_event_loop(loop)
      return asyncio.get_event_loop()


def generate_err_resp(error_msg, http_code):

  return {
    'error': error_msg
  }, http_code


def get_access_control_filepath():
  """
  Returns the filepath of the access control file.

  The Access Control file is either identified by an environment variable or stored in
  config/access.control.ttl

  :return: filepath of the access control
  """
  return os.getenv(constants.ACCESS_CONTROL_FILE_ENV_VAR,
                   os.path.join(constants.PROJECT_DIRECTORY, 'config/access.control.ttl'))


def generate_cryptographic_challenge():
  # TODO: This is not a secure nonce generation.
  return random.randint(10000000000, 100000000000)


def is_webhook_request_input_data_valid(input_data):
  """
  Validates whether the Webhook input complies to the expected input structure.
  Expected Input Structure:
  {
    'sender': <sender_id>,
    'request': {
      'type': <type of received request>
    }
  }

  :param input_data: Received API Input
  :return: True/False
  """
  return (
    'sender' in input_data and
    'request' in input_data and
    'type' in input_data['request']
  )


def is_didcomm_webhook_request_input_data_valid(input_data):
  """
  Validates whether the Webhook input complies to the expected input structure for DIDComm-based Requests.
  Expected Input Structure:
  {
    "sender": "<Peer-DID of the sender of the request>",
    "request": {
      "type": "DIDComm",
      "http_request_method": <GET/POST/PUT/DELETE>,
      "message": {
        "id": <DIDComm Message ID>,
        "type": <DIDComm Message Type>,
        "body": <DIDComm Message Body (plaintext)>,
        "attachments": [
          "<attachment of the DIDComm Message>"
        ]
      }
    }
  }

  :param input_data: Received API Input
  :return: True/False
  """
  return (
    'sender' in input_data and
    'request' in input_data and
    'type' in input_data['request'] and
    'http_request_method' in input_data['request'] and
    'message' in input_data['request'] and
    'id' in input_data['request']['message'] and
    'type' in input_data['request']['message'] and
    'body' in input_data['request']['message'] and
    'attachments' in input_data['request']['message']
  )


def prepare_response_for_didcomm_api(response_http_code, response_msg_type, response_msg_body):
  """
  Prepares a response for the DIDComm_API.
  The response instructs the DIDComm_API how to respond to the received User Request.

  :param response_http_code: HTTP Code of the response to the User Request
  :param response_msg_type: DIDComm Message Type for the response to the User Request
  :param response_msg_body: DIDComm Message Body for the response to the User Request
  :return: Prepared response to be sent to the DIDComm_API
  """
  return {
    "response": {
      "http_code": response_http_code,
      "type": "DIDComm",
      "message": {
        "id": None,
        "type": response_msg_type,
        "body": response_msg_body
      }
    }
  }, constants.HTTP_SUCCESS_STATUS


def is_user_request_message_body_valid(message_body, message_type):
  """
  Validates the Message Body of a User Request.

  :param message_body: Received message body
  :param message_type: Received message type
  :return:
  """
  if message_type == constants.DIDCOMM_INITIAL_REQUEST_MSG_TYPE:
    if 'resource_url' not in message_body:
      logging.warning(f'Invalid User Request Message: Message Type: {message_type}. Missing resource_url')
      return False
    # Valid DIDCOMM_INITIAL_REQUEST_MSG_TYPE user request
    return True

  if message_type == constants.DIDCOMM_PRESENTATION_MSG_TYPE:
    if (
      "resource_url" not in message_body or
      "formats" not in message_body or
      not isinstance(message_body['formats'], list) or
      "presentations~attach" not in message_body or
      not isinstance(message_body['presentations~attach'], list)
    ):
      logging.warning(f'Invalid User Request Message: Message Type: {message_type}. First Level Check')
      return False
    for attachment_format in message_body['formats']:
      if (
        'attach_id' not in attachment_format or
        'format' not in attachment_format
      ):
        logging.warning(f'Invalid User Request Message: Message Type: {message_type}. Attachment Formats Check')
        return False
    for attachment in message_body['presentations~attach']:
      if (
        '@id' not in attachment or
        'mime-type' not in attachment or
        'data' not in attachment
      ):
        logging.warning(f'Invalid User Request Message: Message Type: {message_type}. Attachments Check')
        return False
    # Valid DIDCOMM_PRESENTATION_MSG_TYPE user request
    return True

  # Unrecognized Message Type
  logging.warning(f'Invalid User Request Message: Unrecognized Message Type: {message_type}')
  return False
