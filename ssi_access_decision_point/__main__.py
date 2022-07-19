# -*- coding: utf-8 -*-

"""Main module."""

import logging
from flask import request
from flask_httpauth import HTTPBasicAuth
from ssi_access_decision_point import app_configurer, utils, constants, api_handler


flask_app = app_configurer.initialize_flask_app(__name__)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password):
  auth_config = utils.load_component_configuration('authorization')
  if username == auth_config['username'] and password == auth_config['password']:
    logging.info(f'Successful Authorization with username: {username}')
    return True
  else:
    logging.info(f'Unsuccessful Authorization when using internal API.')
    return False


@flask_app.route('/-system/liveness')
def check_system_liveness():
  return 'ok', constants.HTTP_SUCCESS_STATUS


@flask_app.route(constants.API_MESSAGE_RECEIVED_WEBHOOK, methods=['POST'])
def message_received_webhook():
  if request.method != 'POST':
    logging.error(constants.INVALID_WEBHOOK.format(f"Invalid HTTP Request Method: {request.method}"))
    return utils.generate_err_resp('Invalid Request Method', constants.HTTP_NOT_FOUND)
  if not request.content_type.startswith('application/json'):
    logging.error(constants.INVALID_WEBHOOK.format(f"Invalid Content Type: {request.content_type}"))
    return utils.generate_err_resp('Invalid Request Content Type', constants.HTTP_BAD_REQUEST)

  request_data = request.get_json()

  if not utils.is_webhook_request_input_data_valid(request_data):
    logging.error(constants.INVALID_WEBHOOK.format(f"Invalid Webhook input: {str(request_data)}"))
    return utils.generate_err_resp('Invalid Webhook Input', constants.HTTP_BAD_REQUEST)

  if request_data['request']['type'] == constants.REQUEST_DIDCOMM:
    if not utils.is_didcomm_webhook_request_input_data_valid(request_data):
      logging.error(constants.INVALID_WEBHOOK.format("Webhook's DIDComm Input is invalid"))
      return utils.generate_err_resp('Invalid DIDComm Webhook Input', constants.HTTP_BAD_REQUEST)

    message_type = request_data['request']['message']['type']

    if message_type not in [constants.DIDCOMM_INITIAL_REQUEST_MSG_TYPE, constants.DIDCOMM_PRESENTATION_MSG_TYPE]:
      # Unsupported Message Type -> Instruct DIDComm_API to respond with an error DIDComm message
      logging.warning(constants.INVALID_USER_REQUEST.format(
        f"Unsupported Message Type: {message_type}. Returning error to client "))
      error_response_msg_body = {
        'error': 'Unsupported Message Type: {}'.format(message_type)
      }
      return utils.prepare_response_for_didcomm_api(
        constants.HTTP_BAD_REQUEST, constants.DIDCOMM_ERROR_MSG_TYPE, error_response_msg_body
      )

    if not utils.is_user_request_message_body_valid(request_data['request']['message']['body'], message_type):
      logging.warning(constants.INVALID_USER_REQUEST.format(
        f"Invalid Request Message Body. Message type: {message_type}. Returning error to client."))
      error_response_msg_body = {
        'error': f'Invalid Message Body: Request of type {message_type} failed validation'
      }
      return utils.prepare_response_for_didcomm_api(
        constants.HTTP_BAD_REQUEST, constants.DIDCOMM_ERROR_MSG_TYPE, error_response_msg_body
      )

    #logging.info(constants.USER_REQUEST_RECEIVED.format(message_type))

    if message_type == constants.DIDCOMM_INITIAL_REQUEST_MSG_TYPE:
      return api_handler.handle_initial_user_request(
        request_data['sender'],
        request_data['request']['http_request_method'],
        request_data['request']['message']['id'],
        request_data['request']['message']['body']
      )

    if message_type == constants.DIDCOMM_PRESENTATION_MSG_TYPE:
      return api_handler.handle_secondary_user_request(
        request_data['sender'],
        request_data['request']['http_request_method'],
        request_data['request']['message']['id'],
        request_data['request']['message']['body']
      )

  # Unsupported Request Type. Current only DIDComm-based requests supported -> Bad Request from DIDComm_API
  logging.warning(constants.INVALID_WEBHOOK.format(
    f"Unsupported Request Type: {request_data['request']['type']}"))
  return utils.generate_err_resp(
    "Unsupported Request Type {}".format(request_data['request']['type']),
    constants.HTTP_NOT_FOUND
  )


if __name__ == '__main__':
  server_config = utils.load_component_configuration('server')
  flask_app.run(debug=server_config['debug'], port=server_config['port'], host=server_config['host'])
