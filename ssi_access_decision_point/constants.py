import os
import re

# General service-wide constants
SERVICE_NAME = "ssi_access_decision_point"
LOGGING_CNF_PATH_ENV_VAR = 'LOGGING_CNF_PATH'
CONFIG_FILE_PATH_ENV_VARIABLE = 'CONFIG_PATH'
ACCESS_CONTROL_FILE_ENV_VAR = 'ACCESS_FILE_PATH'
PROJECT_DIRECTORY = os.path.dirname(__file__)

# Domain used as a challenge for Presentation Requests
ACCESS_CONTROL_DOMAIN = "AIFB_SSI_ACCESS_CONTROL_2022"

# Configuration structure
CONF_SERVICES_NAME = "services"

# API Endpoints
API_MESSAGE_RECEIVED_WEBHOOK = '/webhook/message/'

# Regexes
VALID_COMPONENT_NAME_REGEX = re.compile('[a-z_]+')
JWT_REGEX = re.compile(r"^(?:[\w-]*\.){2}[\w-]*$")

# Messages
LOG_CNF_NO_SERVICES = 'Invalid configuration - No services defined'
LOG_CNF_UNAVAIL_SERVICE = f'Invalid configuration - The service configuration ({SERVICE_NAME}) is missing.'
LOG_CNF_COMPONENT_MISSING = 'Unavailable component configuration: %s. ' \
                            'Provide its configuration in the config.yml.'
LOG_INVALID_COMP_NAME = 'Invalid component name: %s. Component names have the following pattern: %s'
LOG_YAML_PARSE_FAIL = 'YAML file {} could not be parsed - {}'

# HTTP STATUS CODES
HTTP_SUCCESS_STATUS = 200
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_ERROR = 500

# HTTP Request Methods
HTTP_GET = 'GET'
HTTP_POST = 'POST'
HTTP_PUT = 'PUT'
HTTP_DELETE = 'DELETE'

# User Request Types
REQUEST_DIDCOMM = "DIDComm"

# DIDComm User Request Message Types
DIDCOMM_INITIAL_REQUEST_MSG_TYPE = "https://uwmbv.solid.aifb.kit.edu/ssi-acs/didcomm/messages/initial-request"
DIDCOMM_REQUEST_PRESENTATION_MSG_TYPE = "https://didcomm.org/present-proof/2.0/request-presentation"
DIDCOMM_PRESENTATION_MSG_TYPE = "https://didcomm.org/present-proof/2.0/presentation"
DIDCOMM_ERROR_MSG_TYPE = "https://uwmbv.solid.aifb.kit.edu/ssi-acs/didcomm/messages/error-message"
DIDCOMM_AUTHORIZATION_DECISION_MSG_TYPE = "http://example.aifb.org/autorization-decision/"

# Attachment formats:
PRESENTATION_REQUEST_ATTACHMENT_FORMAT_PE_DEFINITION = "dif/presentation-exchange/definitions@v1.0"
PRESENTATION_REQUEST_ATTACHMENT_FORMAT_SHACL = "https://uwmbv.solid.aifb.kit.edu/ssi-acs/didcomm/attachments/" \
                                               "required-credentials/SHACL/presentation-request"
PRESENTATION_ATTACHMENT_FORMAT_SHACL = "https://uwmbv.solid.aifb.kit.edu/ssi-acs/didcomm/attachments/" \
                                       "required-credentials/SHACL/presentation"

# Logging
INVALID_WEBHOOK = "Received Invalid Webhook: {}"
INVALID_USER_REQUEST = "Received Invalid User Request: {}"
USER_REQUEST_RECEIVED = "Received User Request. Message Type: {}. Proceeding to handling"
