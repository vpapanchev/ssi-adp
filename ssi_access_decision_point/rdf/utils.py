import logging
import json
from rdflib import Graph
from pyshacl import validate
from ssi_access_decision_point import utils
from ssi_access_decision_point.rdf import sparql


def is_credential_compliant(ld_credential_dict, shacl_shapes_graph_serialized):
  """
  Checks whether a Linked-Data Credential (stored as a Python Dictionary) fulfills a SHACL Shapes Definition.

  The credential is parsed as an RDF Graph which is then validated with the SHACL Shapes.

  :param ld_credential_dict: Linked Data Credential as Python Dictionary
  :param shacl_shapes_graph_serialized: Turtle Serialization of an RDF Graph containing SHACL Shapes
  :return: True iff the credential's RDF Graph fulfills the SHACL Shapes
  """
  shacl_shapes_graph = parse_ttl_graph(shacl_shapes_graph_serialized)
  credential_graph = parse_ld_credential_dict(ld_credential_dict)
  return __is_graph_valid(credential_graph, shacl_shapes_graph)


def is_credential_compliant_graphs(ld_credential_graph, shacl_shapes_graph):
  """
  Checks whether a Linked-Data Credential fulfills a SHACL Shapes Definition.

  The credential and the SHACL Shapes are already provided as RDF Graphs.

  :param ld_credential_graph: Linked Data Credential as RDF Graph
  :param shacl_shapes_graph: RDF Graph containing SHACL Shapes
  :return: True iff the credential's RDF Graph fulfills the SHACL Shapes
  """
  return __is_graph_valid(ld_credential_graph, shacl_shapes_graph)


def parse_ld_credential_dict(credential_dict):
  credential_data = json.dumps(credential_dict)
  credential_graph = Graph()
  credential_graph.parse(data=credential_data, format='json-ld')
  return credential_graph


def __is_graph_valid(rdf_graph, shacl_shapes_graph):
  conforms, v_graph, v_text = validate(rdf_graph, shacl_graph=shacl_shapes_graph,
                                       shacl_graph_format='turtle',
                                       inference='rdfs', debug=False,
                                       serialize_report_graph=True)
  return conforms


def load_required_credentials_shacl_shapes(resource_url, acl_access_mode):
  """
  Parses the Access Control file and finds the Required Credentials SHACL Shapes Graphs for
  a given resource and acl access mode.

  :param resource_url: URL or requested resource
  :param acl_access_mode: Possible values: 'acl:Read' 'acl:Write' 'acl:Append' 'acl:Control'
  :return: [{
    'shacl_graph': Serialized RDF Graph in Turtle Format containing a Required Credential SHACL Definition
    'name': The URIRef of this required credential Shape
  }]
  """
  access_control_graph = load_access_control_graph()

  required_credentials_query = sparql.REQUIRED_CREDENTIALS_QUERY.format(
    resource_url=resource_url, acl_access_mode=acl_access_mode)
  query_result = access_control_graph.query(required_credentials_query)

  required_credentials = []
  no_required_credentials = True
  for row in query_result:
    no_required_credentials = False
    graph_out_of_node_query = sparql.GRAPH_OUT_OF_NODE_QUERY.format(node_uri=row.cred)
    req_cred_graph = access_control_graph.query(graph_out_of_node_query).graph
    required_credentials.append({
      'shacl_graph': serialize_graph_ttl(req_cred_graph),
      'name': row.cred.n3()
    })

  if no_required_credentials:
    # Resource does not have Required Credentials
    # In real-scenario: fallback to the usual Web Access Control implementation
    # In our scenario: this should not happen. Log an error
    logging.error(f"Did not find required credentials for a resource {resource_url} and acl_mode: {acl_access_mode}")

  return required_credentials


def load_access_control_graph():
  """
  Reads and parses the Access Control file as an RDF Graph object.

  :return: Access Control Graph
  """
  access_control_filepath = utils.get_access_control_filepath()
  access_control_graph = Graph()
  access_control_graph.parse(access_control_filepath)

  return access_control_graph


def serialize_graph_ttl(graph):
  return graph.serialize(format='ttl')


def parse_ttl_graph(graph_turtle):
  g = Graph()
  g.parse(data=graph_turtle, format='turtle')
  return g
