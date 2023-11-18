import re

from ssi_access_decision_point import constants
from ssi_access_decision_point.credentials import jwt


def verify_presentation(presentation, nonce, domain):
  """
  Verifies validity, integrity, authenticity of a Verifiable Presentation (VP).
  Presentation and included credentials can be of different types.
  Currently supported:
    - JSON-LD Credentials + JWT Proofs

  The presentation is expected as provided to a aifb/required-credentials/shacl/presentation@v1.0 attachment.

  If everything is verified, the function also returns a list of the contained credentials in W3C format.

  :param presentation:
  :param nonce: The nonce that should be included in the VP. None for no nonce
  :param domain: The domain that should be included in the VP. None for no domain
  :return: {
    'valid': True iff the VP and all included VCs are verified successfully,
    'reason': <Reason for unsuccessful verification in not valid>,
    'holder': <DID of holder of the credentials>,
    'credentials': <list: the W3C Credentials payloads included in this VP>
  }
  """
  jwt_vp = __find_jwt(presentation)
  if jwt_vp:
    # We have a Verifiable Presentation as a JSON Web Token
    return __verify_jwt_vp(jwt_vp, nonce, domain)

  return {
    'valid': False,
    'reason': 'Unsupported type of Verifiable Presentation. Currently supported: JSON-LD+JWT',
    'holder': None,
    'credentials': None
  }


def __verify_jwt_vp(jwt_vp, nonce, domain):
  vp_verification_result = jwt.verify_jwt_vp(jwt_vp)
  if not vp_verification_result['valid']:
    # Invalid VP
    return {
      'valid': False,
      'reason': vp_verification_result['error'] if vp_verification_result['error'] else "",
      'holder': None,
      'credentials': None
    }

  if nonce != vp_verification_result['data']['challenge']['nonce']:
    return {
      'valid': False,
      'reason': "Required nonce missing in VP",
      'holder': None,
      'credentials': None
    }
  if domain != vp_verification_result['data']['challenge']['domain']:
    return {
      'valid': False,
      'reason': "Required domain missing in VP",
      'holder': None,
      'credentials': None
    }

  # Valid VP with verified nonce and domain -> Verify Credentials of the VP
  verified_credentials, error_msg = __verify_credentials_of_presentation(
    vp_verification_result['data']['verifiablePresentation'], vp_verification_result['data']['holder'])
  if error_msg:
    return {
      'valid': False,
      'reason': error_msg,
      'holder': None,
      'credentials': None
    }
  else:
    return {
      'valid': True,
      'reason': None,
      'holder': vp_verification_result['data']['holder'],
      'credentials': verified_credentials
    }


def __verify_credentials_of_presentation(w3c_presentation, holder):
  """
  Verifies the Verifiable Credentials included in a W3C Verifiable Presentation.
  If the verification of any credential fails, an error message is returned.
  Also verifies that the holder of the VP matches the credentialSubject in each credential.

  :param w3c_presentation:
  :param holder:
  :return: [list<Verified Credential in W3C format>], Error_message
  """
  if 'verifiableCredential' not in w3c_presentation or not w3c_presentation['verifiableCredential']:
    return None, "Missing verifiableCredential field in the Verifiable Presentation"
  credentials = w3c_presentation['verifiableCredential']
  if not isinstance(credentials, list):
    credentials = [credentials]

  verified_credentials = []
  for credential in credentials:
    # If the verification of any credentials fails -> Return None, error_msg
    vc_verification_result = verify_credential(credential)
    if not vc_verification_result['valid']:
      return None, "Verification of included credential failed due to: {}".format(vc_verification_result['reason'])
    if holder != vc_verification_result['holder']:
      return None, 'Holder of VP is different from credential subject'

    verified_credentials.append(vc_verification_result['credential'])

  return verified_credentials, None


def verify_credential(credential):
  """
  Verifies validity, integrity, authenticity of a Verifiable Credential (VC).
  Currently supported:
    - JSON-LD Credentials + JWT Proofs

  :param credential:
  :return: {
    'valid': True iff the VC is verified successfully,
    'reason': <Reason for the unsuccessful verification in not valid>,
    'holder': <ID of credential subject>,
    'credential': <the credential in W3C format>
  }
  """
  jwt_vc = __find_jwt(credential)
  if jwt_vc:
    # We have a Verifiable Credential as a JSON Web Token
    vc_verification_result = jwt.verify_jwt_vc(jwt_vc)
    if not vc_verification_result['valid']:
      # Invalid VC
      return {
        'valid': False,
        'reason': vc_verification_result['error'] if vc_verification_result['error'] else "",
        'holder': None,
        'credential': None
      }
    # Valid VC
    cred = vc_verification_result['data']['verifiableCredential']
    return {
      'valid': True,
      'reason': "",
      'holder': __get_credential_subject_id_of_credential(cred),
      'credential': cred
    }

  return {
    'valid': False,
    'reason': 'Unsupported type of Verifiable Credential. Currently supported: JSON-LD+JWT',
    'holder': None,
    'credential': None
  }


def __find_jwt(payload):
  """
  Searches for a JSON Web Token in the payload.

  :param payload: Some payload to be searched. String or Dict or anything
  :return: The JWT is found or None
  """
  if (
    isinstance(payload, str) and
    re.fullmatch(constants.JWT_REGEX, payload)
  ):
    return payload
  if (
    isinstance(payload, dict) and
    "jwt" in payload and
    re.fullmatch(constants.JWT_REGEX, payload["jwt"])
  ):
    return payload['jwt']
  return None


def __get_credential_subject_id_of_credential(credential_payload):
  if 'credentialSubject' not in credential_payload:
    return None
  if 'id' in credential_payload['credentialSubject']:
    return credential_payload['credentialSubject']['id']
  if '@id' in credential_payload['credentialSubject']:
    return credential_payload['credentialSubject']['@id']
  return None
