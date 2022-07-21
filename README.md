### Parent project

This project was developed as a Microservice in the design of the [Interoperable SSI Access Control System (ACS)](https://git.scc.kit.edu/uwmbv/ssi-acs).

# SSI Access Decision Point

## Description
The SSI Access Decision Point (**ADP**) is a python project built using the Flask framework.

ADP plays the role of the core logic component for the [SSI Access Control System (ACS)](https://github.com/vpapanchev/ssi-acs). \
The Access Control Logic is based on [Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/) and [Verifiable Credentials (VCs)](https://www.w3.org/TR/vc-data-model/). \
ADP provides the following functionality:

- **API for Handling User Requests**: Using the provided HTTP API, ADP is notified (usually by [DID-Comm-API](https://github.com/vpapanchev/did-comm-api)) whenever new User Requests are received. Currently, the user requests are in the form of HTTP Requests containing DIDComm Messages. ADP handles the user requests depending on the DIDComm Message type, content and the defined Access Control and instructs the caller of the API (DID-Comm-API) on how to respond to the received HTTP Requests.

- **Access Control Logic**: ADP stores and manages the authorization rules which define the access control logic for all resources protected by the ACS. The authorization rules are defined based on the [Web Access Control](https://solid.github.io/web-access-control-spec/) but also describe required types of VCs. Based on the authorization rules and their descriptions of required credentials, ADP creates Verifiable Presentation Requests (VPRs) when handling user requests. An example [access control file](https://github.com/vpapanchev/ssi-adp/blob/main/ssi_access_decision_point/config/access.control.ttl) is provided.

- **Exchange of Credentials**: ADP implements a protocol for exchange of Verifiable Credentials. The protocol is based on the [HL Aries RFC 0454: Present Proof Protocol 2.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0454-present-proof-v2/README.md). The DIDComm Messages of this protocol may contain attachments representing VPRs and Verifiable Presentations (VPs) in different formats. The supported attachments formats are listed below.

- **Verification of Verifiable Presentations and Credentials**: ADP finds out the type of the received credentials and presentations and verifies them using external components such as the [VC-JWT-Verifier](https://github.com/vpapanchev/vc-jwt-verifier). Supported types of credentials are listed below.

#### Supported Formats for VPRs and VPs attachments

Currently, only our own format for VPRs is supported - https://uwmbv.solid.aifb.kit.edu/ssi-acs/didcomm/attachments/required-credentials/SHACL/presentation-request \
However, implementing support for [DIF Presentation Exchange](https://identity.foundation/presentation-exchange/) will be beneficial for interoperability with other SSI systems.

#### Supported types of Verifiable Credentials

Currently, only Linked-Data Credentials with JSON Web Token Proofs are supported.

## Installation

### How to run locally

1. Open the configuration file `/ssi_access_decision_point/config/config.yml` and set the server host, port and the APIs for connecting to the VC Verifiers.
2. Create and activate a new virtual environment:\
`python3 -m venv ./venv`\
`source venv/bin/activate`
3. Install the project requirements\
`pip3 install -r requirements_dev.txt`
4. Run \
`python3 -m ssi_access_decision_point`

### How to run using Docker

1. Open the configuration file `/ssi_access_decision_point/config/config.yml` and set the server host, port and the APIs for connecting to the VC Verifiers.
2. Run \
`docker build -f docker/Dockerfile --tag adp-image .`\
`docker run -p <port>:<port> --env API_PORT=<port> --name=adp adp-image:latest`
3. To see the logs of the container:\
`docker logs adp`
4. To stop the container:\
`docker stop adp`

## Usage

To notify ADP when a new User Request has been received, send an HTTP POST Request to the ADP's API: **http://<adp_ip:port>/webhook/message/** \
ADP listens for POST HTTP Requests and expects requests with Content-Type set to **application/json** and the following message body structure:
```json
{
  "sender": "<Identifier of Sender of the request, usually a Peer-DID>",
  "request": {
    "type": "DIDComm",
    "http_request_method": "HTTP Request Method of received request - one of GET/POST/PUT/DELETE",
    "message": {
      "id": "<DIDComm Message ID>",
      "type": "<DIDComm Message Type>",
      "body": {
        "_comment": "The DIDComm Message Body in plaintext as JSON Object"
      }
      "attachments": [
        {
          "_comment": "List of DIDComm Message Attachments as JSON Objects",
          "_comment": "Currently not used. In the future VPRs and VPs may be sent as DIDComm attachments"
        }
      ]
    }
  }
}

```
ADP handles the received message and instructs the caller of the API on how to respond to the received user request. Currently, only DIDComm Messages over HTTP are supported, so the ADP response specifies what HTTP Response containing what DIDComm Message to send back to the user. For this, the ADP's API responds have the following structure:
```json
{
  "response": {
    "http_code": "<HTTP Status Code of the HTTP Response. Example: 200>",
    "type": "DIDComm",
    "message": {
      "id": "<Message_ID of the DIDComm Message. None if random message_id can be used>",
      "type": "<Message_Type of the DIDComm Message>",
      "body": "<Message_Body of the DIDComm Message>"
    }
  }
}
```


## Support

In case of questions about the project use the following contacts:\
Email: vasilpapanchev@gmail.com

## Project status

The project was created as a prototype used for evaluating purposes and might not be actively supported in the future.
