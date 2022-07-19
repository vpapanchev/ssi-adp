import json
import logging
import base64
import secrets
import time

from ssi_access_decision_point import utils, constants
from ssi_access_decision_point.rdf import utils as rdf_utils
from ssi_access_decision_point.db import operations
from ssi_access_decision_point.credentials import verifier

# Logging constants
LOG_HANDLING_IR = "Handling Initial User Request: Message_ID: {} Resource_url: {} HTTP Method: {}"
LOG_HANDLED_IR_SENT_PR = "Handled Initial Request with Message_ID: {}: Requesting Credentials: {}"
LOG_HANDLED_IR_NOT_FOUND = "Handled Initial Request with Message_ID: {}: Returning 404 Not Found."

LOG_HANDLING_SR = "Handling Secondary User Request: Message_ID: {} Resource_url: {} HTTP Method: {}"

LOG_HANDLED_SR_MISSING_IR = "Handled Secondary Request with Message_ID: {}: " \
                            "Could not find a corresponding Initial Request. Sending 400 Bad Request to Client."
LOG_HANDLED_SR_MISSING_VP = "Handled Secondary Request with Message_ID: {}: " \
                            "Could not find a VP in the request. Sending 400 Bad Request to Client."
LOG_HANDLED_SR_INVALID_VP = "Handled Secondary Request with Message_ID: {}: " \
                            "Verification of VP failed with: {}. Returning 403 Forbidden to client."
LOG_HANDLED_SR_UNSATISFIED_CREDENTIALS = "Handled Secondary Request with Message_ID: {}: " \
                                         "Provided credentials do not satisfy required credentials. " \
                                         "Returning 403 Forbidden to client"
LOG_HANDLED_SR_SUCCESS = "Handled Secondary Request with Message_ID: {}: " "Successful authorization: " \
                         "Client Communication DID: {}, " \
                         "Requested Resource: {}, " \
                         "Access mode: {}"

LOG_INVALID_VP_MISSING_ATTACHMENT = f"Received Invalid VP: " \
                                    f"Could not find a {constants.PRESENTATION_ATTACHMENT_FORMAT_SHACL} attachment."
LOG_INVALID_VP_ATTACHMENT = "Received Invalid VP: " \
                            "Neither of data:json:jwt , data:json:w3c, data:base64 found"


def handle_initial_user_request(sender, http_request_method, msg_id, msg_body):
  """
  Handles a received Initial User Request.
  Request's DIDComm Message Type: http://example.aifb.org/resource/initial-request@v1.0

  Finds out the access control rules for the requested resource and operation and creates a Presentation Request.
  Instructs DIDComm API to respond to the Client Request with the Presentation Request and HTTP Code: 401 Unauthorized

  :param sender: Communication (Peer-)DID of the sender of the request
  :param http_request_method: Requested HTTP Method on the resource (GET/POST/PUT/DELETE/..)
  :param msg_id: Message_ID of the received DIDComm Message
  :param msg_body: Message_Body of the received DIDComm Message
  :return: Response for the DID_Communication_API. see utils.prepare_response_for_didcomm_api()
  """

  # We have a "http://example.aifb.org/resource/initial-request@v1.0" Request
  resource_url = msg_body['resource_url']
  acl_access_mode = __http_method_to_acl_mode(http_request_method)
  #logging.info(LOG_HANDLING_IR.format(msg_id, resource_url, http_request_method))

  # Get Required Credential SHACL Definitions
  required_credentials = rdf_utils.load_required_credentials_shacl_shapes(resource_url, acl_access_mode)
  if not required_credentials:
    # No required credentials found for this resource. Future work. Return 404
    logging.info(LOG_HANDLED_IR_NOT_FOUND.format(msg_id))
    return utils.prepare_response_for_didcomm_api(
      constants.HTTP_NOT_FOUND, constants.DIDCOMM_ERROR_MSG_TYPE, {'error': 'Resource not found'}
    )
  req_creds_graphs_turtle = []
  req_creds_names = []
  for req_cred in required_credentials:
    req_creds_graphs_turtle.append(req_cred['shacl_graph'])
    req_creds_names.append(req_cred['name'])

  # Get Domain and Nonce
  nonce = __generate_challenge_nonce()
  domain = __get_challenge_domain()

  # Create the Presentation Request
  req_credentials_dict = {
    "required_credentials": req_creds_graphs_turtle,
    "options": {
      "challenge": nonce,
      "domain": domain,
    }
  }
  req_creds_string = json.dumps(req_credentials_dict)
  req_creds_b64 = base64.urlsafe_b64encode(req_creds_string.encode('utf-8')).decode('utf-8')

  # Get Presentation Exchange Presentation Definition
  pe_presentation_definition = required_credentials_shacl_to_pe(req_creds_graphs_turtle)

  # Store the User Request in Database
  operations.store_new_user_request(sender, resource_url, http_request_method, req_creds_b64)

  # Create Presentation Request
  response_msg_body = __create_presentation_request(nonce, domain, pe_presentation_definition, req_creds_b64)

  # Send response back to Client
  #logging.info(LOG_HANDLED_IR_SENT_PR.format(msg_id, req_creds_names))
  return utils.prepare_response_for_didcomm_api(
    constants.HTTP_UNAUTHORIZED, constants.DIDCOMM_REQUEST_PRESENTATION_MSG_TYPE, response_msg_body)


def __http_method_to_acl_mode(http_request_method):
  if http_request_method == constants.HTTP_GET:
    return 'acl:Read'
  if http_request_method == constants.HTTP_PUT:
    return 'acl:Write'
  if http_request_method == constants.HTTP_POST:
    return 'acl:Append'
  if http_request_method == constants.HTTP_DELETE:
    return 'acl:Write'
  logging.warning(f"Unrecognized HTTP Request Method: {http_request_method}!")
  return 'acl:Write'


def __generate_challenge_nonce():
  return secrets.token_urlsafe()


def __get_challenge_domain():
  return constants.ACCESS_CONTROL_DOMAIN


def required_credentials_shacl_to_pe(required_credentials):
  """
  Translates the required credentials from SHACL Graphs to DIF's Presentation Exchange.
  TODO: Future Work

  :param required_credentials: required credentials as list of SHACL Shapes Graphs
  :return: DIF PE Presentation Definition
  """
  return "UNSUPPORTED"


def __create_presentation_request(nonce, domain, pe_presentation_definition, shacl_presentation_request_b64):
  return {
    "will_confirm": False,
    "present_multiple": False,
    "formats": [
      {
        "attach_id": "attachment_1",
        "format": constants.PRESENTATION_REQUEST_ATTACHMENT_FORMAT_PE_DEFINITION,
      },
      {
        "attach_id": "attachment_2",
        "format": constants.PRESENTATION_REQUEST_ATTACHMENT_FORMAT_SHACL,
      }
    ],
    "request_presentations~attach": [
      {
        "@id": "attachment_1",
        "mime-type": "application/json",
        "data": {
          "json": {
            "options": {
              "challenge": nonce,
              "domain": domain,
            },
            "presentation_definition": pe_presentation_definition
          }
        }
      },
      {
        "@id": "attachment_2",
        "mime-type": "application/json",
        "data": {
          "base64": shacl_presentation_request_b64
        }
      }
    ]
  }


def handle_secondary_user_request(sender, request_http_method, msg_id, msg_body):
  """
  Handles a received Secondary User Request.
  Request's DIDComm Message Type: https://didcomm.org/present-proof/2.0/presentation

  Finds the stored Initial User Request and its Presentation Request.
  Validates the Verifiable Presentation inside this request against the stored Presentation Request.
  Makes an authorization decision.
  Instructs DID_Communication_API how to respond to the Client.

  :param sender: Communication (Peer-)DID of the sender of the request
  :param request_http_method: Requested HTTP Method on the resource (GET/POST/PUT/DELETE/..)
  :param msg_id: Message_ID of the received DIDComm Message
  :param msg_body: Message_Body of the received DIDComm Message
  :return: Response for the DID_Communication_API. see utils.prepare_response_for_didcomm_api()
  """
  start_handle = time.time()
  resource_url = msg_body['resource_url']
  #logging.info(LOG_HANDLING_SR.format(msg_id, resource_url, request_http_method))

  # Get the corresponding Initial Request
  start_get_stored_context = time.time()
  initial_request = __get_stored_initial_request(sender, resource_url, request_http_method)
  if not initial_request:
    logging.info(LOG_HANDLED_SR_MISSING_IR.format(msg_id))
    error_response_msg_body = {
      'error': f'The received {constants.DIDCOMM_PRESENTATION_MSG_TYPE} message cannot be'
               f' mapped to an existing {constants.DIDCOMM_INITIAL_REQUEST_MSG_TYPE} request.'
    }
    return utils.prepare_response_for_didcomm_api(
      constants.HTTP_BAD_REQUEST, constants.DIDCOMM_ERROR_MSG_TYPE, error_response_msg_body
    )
  initial_request_id = initial_request['id']

  # Get nonce, domain and required credentials from the stored Presentation Request
  presentation_request = __get_presentation_request_from_initial_request(initial_request)
  nonce = presentation_request['options']['challenge']
  domain = presentation_request['options']['domain']
  req_creds_graphs_turtle = presentation_request['required_credentials']
  # logs: 'adp_get_stored_context_for_request,<msg_id>,<time>'
  logging.info(f"adp_get_stored_context_for_request,{msg_id},{time.time() - start_get_stored_context}")

  verifiable_presentation = __get_vp_from_presentation_msg_body(msg_body)
  if not verifiable_presentation:
    error_response_msg_body = {
      'error': 'Could not find a Verifiable Presentation in the DIDComm Message'
    }
    logging.info(LOG_HANDLED_SR_MISSING_VP.format(msg_id))
    return utils.prepare_response_for_didcomm_api(
      constants.HTTP_BAD_REQUEST, constants.DIDCOMM_ERROR_MSG_TYPE, error_response_msg_body
    )

  # Verify Presentation and Credentials
  start_vp_verify = time.time()
  verification_result = verifier.verify_presentation(verifiable_presentation, nonce, domain)
  if not verification_result['valid']:
    reason = verification_result['reason']
    response_msg_body = {
      'authorized': False,
      'error': 'Verification of Verifiable Presentation failed with: {}'.format(reason)
    }
    logging.info(LOG_HANDLED_SR_INVALID_VP.format(msg_id, reason))
    return utils.prepare_response_for_didcomm_api(
      constants.HTTP_FORBIDDEN, constants.DIDCOMM_ERROR_MSG_TYPE, response_msg_body
    )

  # Log successful verify_vp times
  holder_did = verification_result['holder']
  num_creds = len(verification_result['credentials'])
  # logs: 'adp_verify_vp,<msg_id>,<holder_did>,<number_creds_in_VP>,<time>'
  logging.info(f"adp_verify_vp,{msg_id},{holder_did},{num_creds},{time.time() - start_vp_verify}")

  # Check whether the provided credentials fulfil the required ones
  start_check_required_creds = time.time()
  provided_credentials = verification_result['credentials']
  required_credentials_fulfilled = __check_provided_credentials_against_required_ones(
    provided_credentials, req_creds_graphs_turtle)
  if not required_credentials_fulfilled:
    response_msg_body = {
      'authorized': False,
      'error': 'Provided credentials do not satisfy the required credentials'
    }
    logging.info(LOG_HANDLED_SR_UNSATISFIED_CREDENTIALS.format(msg_id))
    return utils.prepare_response_for_didcomm_api(
      constants.HTTP_FORBIDDEN, constants.DIDCOMM_ERROR_MSG_TYPE, response_msg_body
    )
  # logs: 'apd_check_required_creds,<msg_id>,<time>'
  logging.info(f"adp_check_required_creds,{msg_id},{time.time() - start_check_required_creds}")

  # Delete the stored Initial Request
  operations.delete_user_request(initial_request_id)

  # how much time it took to handle a valid request
  # logs: 'adp_handle_secondary,<msg_id>,<holder_did>,<time>'
  logging.info(f"adp_handle_secondary,{msg_id},{holder_did},{time.time() - start_handle}")

  # Approve the request
  #logging.info(LOG_HANDLED_SR_SUCCESS.format(
  #  msg_id, sender, resource_url, __http_method_to_acl_mode(request_http_method)))
  return utils.prepare_response_for_didcomm_api(
    constants.HTTP_SUCCESS_STATUS, constants.DIDCOMM_AUTHORIZATION_DECISION_MSG_TYPE, {'authorized': True})


def __get_stored_initial_request(sender, resource_url, request_http_method):
  stored_requests = operations.get_user_requests(sender)
  for stored_request in stored_requests:
    if (
      stored_request['resource_url'] == resource_url and
      stored_request['http_request_method'] == request_http_method
    ):
      return stored_request


def __get_presentation_request_from_initial_request(initial_request):
  presentation_request_b64 = initial_request['presentation_request']
  presentation_request_dict_dumped = base64.urlsafe_b64decode(presentation_request_b64.encode('utf-8')).decode('utf-8')
  presentation_request = json.loads(presentation_request_dict_dumped)
  return presentation_request


def __get_vp_from_presentation_msg_body(msg_body):
  """
  Parses a https://didcomm.org/present-proof/2.0/presentation Message Body and finds the Verifiable Presentation

  Currently supported attachment formats:
  - "aifb/required-credentials/shacl/presentation@v1.0"

  :param msg_body: Message Body of a DIDComm Message of type https://didcomm.org/present-proof/2.0/presentation
  :return: The VP of this presentation
  """

  attachment_id = None
  for attachment_format in msg_body['formats']:
    if attachment_format['format'] == constants.PRESENTATION_ATTACHMENT_FORMAT_SHACL:
      attachment_id = attachment_format['attach_id']

  if not attachment_id:
    logging.warning(LOG_INVALID_VP_MISSING_ATTACHMENT)
    return None

  presentation_attachment = None
  for attachment in msg_body['presentations~attach']:
    if attachment['@id'] == attachment_id:
      presentation_attachment = attachment

  if not presentation_attachment:
    logging.warning(LOG_INVALID_VP_MISSING_ATTACHMENT)
    return None

  if 'json' in presentation_attachment['data']:
    if 'jwt' in presentation_attachment['data']['json']:
      return presentation_attachment['data']['json']['jwt']
    if 'w3c' in presentation_attachment['data']['json']:
      return presentation_attachment['data']['json']['w3c']

    logging.warning(LOG_INVALID_VP_ATTACHMENT)
    return None

  if 'base64' in presentation_attachment['data']:
    vp_b64 = presentation_attachment['data']['base64']
    vp_dict_dumped = base64.urlsafe_b64decode(vp_b64.encode('utf-8')).decode('utf-8')
    return json.loads(vp_dict_dumped)

  logging.warning(LOG_INVALID_VP_ATTACHMENT)
  return None


def __check_provided_credentials_against_required_ones(credentials, required_creds_graphs_turtle):
  """
  Checks whether each of the required_credentials is fulfilled by at least one of the provided credentials.

  :param credentials:
  :param required_creds_graphs_turtle: List of Turtle-Serialized RDF Graphs containing SHACL Definitions
  :return: True iff every required credential is fulfilled by at least one of the provided credentials
  """
  # Parse credentials as RDF Graphs
  credentials_graphs = []
  for credential in credentials:
    credentials_graphs.append(rdf_utils.parse_ld_credential_dict(credential))

  # Parse Required Credential SHACL Definitions as RDF Graphs
  required_creds_graphs = []
  for required_credential_shacl_graph_ttl in required_creds_graphs_turtle:
    required_creds_graphs.append(rdf_utils.parse_ttl_graph(required_credential_shacl_graph_ttl))

  # Check whether each required credential is satisfied by at least 1 of the credentials
  for required_credential_graph in required_creds_graphs:
    fulfilled = False
    for credential_graph in credentials_graphs:
      if rdf_utils.is_credential_compliant_graphs(credential_graph, required_credential_graph):
        fulfilled = True
        break
    if not fulfilled:
      return False
  return True
