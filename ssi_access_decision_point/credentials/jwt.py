""" Verifier for W3C Verifiable Credentials and Presentation in JSON-LD Syntax with JWT Proofs """

import requests
import logging

from ssi_access_decision_point import utils, constants

def verify_jwt_vp_with_credentials(jwt_vp):
  """
  Verifies a W3C Verifiable Presentation in JSON-LD syntax with JWT proofs.

  NB: Also directly verifies the included credentials in the VP.
  Assumes, that all included VCs are also JWTs.

  Verification is outsourced to another component: VC_JWT_Verifier
  Expected resolution of all DIDs to be executed in parallel!

  Format of output depends on VC_JWT_Verifier.
  Expected output given below.

  :param jwt_vp: Verifiable Presentation encoded as JSON Web Token
  :return: {
    "valid": True/False: Whether the VP is verified,
    "error": "<Reason in case the VP is not valid>",
    "data": {
      "payload": <decoded_jwt_payload>,
      "holder": <decoded_jwt_payload['iss'] = Holder of the VP>,
      "jwt": <the JWT (same as input)>,
      "verifiablePresentation": <The JWT Payload translated to W3C VP format>,
      "challenge": {
        "nonce": <nonce contained in VP or None>,
        "domain": <domain contained in VP or None>
      }
    } or None if not valid
  }
  """

  credentials_config = utils.load_component_configuration('credentials')
  verify_vp_url = credentials_config['verifiers']['jwt']['verify_vp_complete_url']
  try:
    response = requests.get(verify_vp_url.format(jwt_vp=jwt_vp))
  except requests.exceptions.RequestException as requests_error:
    logging.error(f'Got a RequestsException when connecting to VC_JWT_VERIFIER: {str(requests_error)}')
    return {'valid': False, 'error': 'Could not verify Presentation', 'data': None}

  response_data = response.json()
  if response.status_code != constants.HTTP_SUCCESS_STATUS:
    error_msg = f"Response from VC_JWT_Verifier with status code: {response.status_code}."
    if 'error' in response_data:
      error_msg = error_msg + f" Error: {response_data['error']}"
    logging.error(error_msg)
    return {'valid': False, 'error': 'Could not verify Presentation', 'data': None}

  if not __is_jwt_vp_verification_api_response_valid(response_data):
    logging.error("Unexpected response structure from JWT_VC_Verifier.")
    return {'valid': False, 'error': 'Could not verify Presentation', 'data': None}

  return response_data


def verify_jwt_vp(jwt_vp):
  """
  Verifies a W3C Verifiable Presentation in JSON-LD syntax with JWT proofs.

  NB: Does not automatically verify the included credentials in the VP!

  Verification is outsourced to another component: VC_JWT_Verifier

  Format of output depends on VC_JWT_Verifier.
  Expected output given below.

  :param jwt_vp: Verifiable Presentation encoded as JSON Web Token
  :return: {
    "valid": True/False: Whether the VP is verified,
    "error": "<Reason in case the VP is not valid>",
    "data": {
      "payload": <decoded_jwt_payload>,
      "holder": <decoded_jwt_payload['iss'] = Holder of the VP>,
      "jwt": <the JWT (same as input)>,
      "verifiablePresentation": <The JWT Payload translated to W3C VP format>,
      "challenge": {
        "nonce": <nonce contained in VP or None>,
        "domain": <domain contained in VP or None>
      }
    } or None if not valid
  }
  """

  credentials_config = utils.load_component_configuration('credentials')
  verify_vp_url = credentials_config['verifiers']['jwt']['verify_vp_only_url']
  try:
    response = requests.get(verify_vp_url.format(verify_credentials='false', jwt_vp=jwt_vp))
  except requests.exceptions.RequestException as requests_error:
    logging.error(f'Got a RequestsException when connecting to VC_JWT_VERIFIER: {str(requests_error)}')
    return {'valid': False, 'error': 'Could not verify Presentation', 'data': None}

  response_data = response.json()
  if response.status_code != constants.HTTP_SUCCESS_STATUS:
    error_msg = f"Response from VC_JWT_Verifier with status code: {response.status_code}."
    if 'error' in response_data:
      error_msg = error_msg + f" Error: {response_data['error']}"
    logging.error(error_msg)
    return {'valid': False, 'error': 'Could not verify Presentation', 'data': None}

  if not __is_jwt_vp_verification_api_response_valid(response_data):
    logging.error("Unexpected response structure from JWT_VC_Verifier.")
    return {'valid': False, 'error': 'Could not verify Presentation', 'data': None}

  return response_data


def verify_jwt_vc(jwt_vc):
  """
  Verifies a W3C Verifiable Credential in JSON-LD syntax with a JWT proof.

  Verification is outsourced to another component: VC_JWT_Verifier

  Format of output depends on VC_JWT_Verifier.
  Expected output given below.

  :param jwt_vc: Verifiable Credential encoded as a JSON Web Token
  :return: {
    "valid": True/False: Whether the VP is verified,
    "error": "<Reason in case the VP is not valid>",
    "data": {
      'payload': decoded_jwt_payload,
      'issuer': <w3c_payload['issuer'] = Issuer of the credential>,
      'jwt': <the JWT (same as input)>,
      'verifiableCredential': <The JWT Payload translated to W3C VC format>
    } or None if not valid
  }
  """
  credentials_config = utils.load_component_configuration('credentials')
  verify_vc_url = credentials_config['verifiers']['jwt']['verify_vc_url']
  try:
    response = requests.get(verify_vc_url.format(jwt_vc=jwt_vc))
  except requests.exceptions.RequestException as requests_error:
    logging.error(f'Got a RequestsException when connecting to VC_JWT_VERIFIER: {str(requests_error)}')
    return {'valid': False, 'error': 'Could not verify Credential', 'data': None}

  response_data = response.json()
  if response.status_code != constants.HTTP_SUCCESS_STATUS:
    error_msg = f"Response from VC_JWT_Verifier with status code: {response.status_code}."
    if 'error' in response_data:
      error_msg = error_msg + f" Error: {response_data['error']}"
    logging.error(error_msg)
    return {'valid': False, 'error': 'Could not verify Credential', 'data': None}

  if not __is_jwt_vc_verification_api_response_valid(response_data):
    logging.error("Unexpected response structure from JWT_VC_Verifier.")
    return {'valid': False, 'error': 'Could not verify Credential', 'data': None}

  return response_data


def __is_jwt_vc_verification_api_response_valid(response):
  """
  Expected response structure:
  {
    'valid': ,
    'error': "",
    'data': None or {
      'payload': decoded_jwt_payload,
      'issuer': w3c_payload['issuer'],
      'jwt': jwt_vc,
      'verifiableCredential': w3c_payload
    }
  }
  :param response: The verification response of the JWT_VC_Verifier for a Credential
  :return: True/False
  """
  if (
    'valid' not in response or
    'error' not in response or
    'data' not in response
  ):
    return False

  if response['valid'] and (
    not response['data'] or
    'payload' not in response['data'] or
    'issuer' not in response['data'] or
    'jwt' not in response['data'] or
    'verifiableCredential' not in response['data']
  ):
    return False
  return True


def __is_jwt_vp_verification_api_response_valid(response):
  """
  Expected response structure:
  {
    'valid': True,
    'error': "",
    'data': None or {
      'payload': decoded_jwt_payload,
      'holder': decoded_jwt_payload['iss'],
      'jwt': jwt_vp,
      'verifiablePresentation': w3c_vp_payload,
      'challenge': {
        'nonce': nonce,
        'domain': domain
      }
    }
  }
  :param response:
  :return:
  """
  if (
    'valid' not in response or
    'error' not in response or
    'data' not in response
  ):
    return False

  if response['valid'] and (
    not response['data'] or
    'payload' not in response['data'] or
    'holder' not in response['data'] or
    'jwt' not in response['data'] or
    'verifiablePresentation' not in response['data'] or
    'challenge' not in response['data'] or
    'nonce' not in response['data']['challenge'] or
    'domain' not in response['data']['challenge']
  ):
    return False
  return True
