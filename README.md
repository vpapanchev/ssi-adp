### Parent project

This project was developed as a Microservice in the design of the [Interoperable SSI Access Control System (ACS)](https://git.scc.kit.edu/uwmbv/ssi-acs).

# SSI Access Decision Point

## Description
The SSI Access Decision Point (**ADP**) is a python project built using the Flask framework.

ADP plays the role of the core logic component for the [SSI Access Control System (ACS)](https://git.scc.kit.edu/uwmbv/ssi-acs). \
The Access Control Logic is based on [Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/) and [Verifiable Credentials (VCs)](https://www.w3.org/TR/vc-data-model/). \
ADP provides the following functionality:

- **API for Handling User Requests**: Using the provided HTTP API, ADP is notified (usually by [DID_Comm_API](https://git.scc.kit.edu/uwmbv/did_communication_api_v2)) whenever new User Requests (in the form of HTTP Requests containing DIDComm Messages) are received. ADP handles the user requests depending on the DIDComm Message type and the defined Access Control and instructs the caller of the API on how to respond to the received HTTP Requests.

- **Access Control Logic**: ADP stores and manages the authorization rules which define the access control logic for all resources protected by the ACS. The authorization rules are defined based on [Web Access Control](https://solid.github.io/web-access-control-spec/) but also describe required types of VCs. Based on the authorization rules and their descriptions of required credentials, ADP creates Verifiable Presentation Requests (VPRs) when handling user requests.

- **Exchange of Credentials**: ADP implements a protocol for exchange of Verifiable Credentials. The protocol is based on the [HL Aries RFC 0454: Present Proof Protocol 2.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0454-present-proof-v2/README.md). The DIDComm Messages of this protocol may contain attachments representing VPRs and Verifiable Presentations (VPs) in different formats. The supported attachments formats are listed below.

- **Verification of Verifiable Presentations and Credentials**: Verification of the received VPs and VCs. ADP finds out the type of the provided credentials and verifies them using external components such as the [VC_JWT_Verifier](https://git.scc.kit.edu/uwmbv/vc_jwt_verifier). Supported types of credentials are listed below.

#### Supported Attachments for VPRs and VPs

TODO

#### Supported types of Verifiable Credentials

Currently, only Linked-Data Credentials with JSON Web Token Proofs are supported.

## Visuals

## Installation

### How to run locally

1. Copy the configuration file:\
`cp ./ssi_access_decision_point/config/config.example.yml ./ssi_access_decision_point/config/config.yml`
2. Open the configuration file and set the server host, port and the APIs for connecting to the VC Verifiers.
3. Create and activate a new virtual environment:\
`python3 -m venv ./venv`\
`source venv/bin/activate`
4. Install the project requirements\
`pip3 install -r requirements_dev.txt`
5. Run \
`python3 -m ssi_access_decision_point`

### How to run using Docker

1. Copy the configuration file:\
`cp ./ssi_access_decision_point/config/config.example.yml ./ssi_access_decision_point/config/config.yml`
2. Open the configuration file and set the server host, port and the APIs for connecting to the VC Verifiers.
3. Run \
`docker build -f docker/Dockerfile --tag adp-image .`\
`docker run -p <port>:<port> --env API_PORT=<port> --name=adp adp-image:latest`
4. To see the logs of the container:\
`docker logs adp`
5. To stop the container:\
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

The project was created as a prototype used for evaluating purposes and will not be actively supported in the future.
