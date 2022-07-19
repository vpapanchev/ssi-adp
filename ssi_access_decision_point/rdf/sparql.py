""" Stores some SPARQL Queries """

# Returns subgraph of graph: tree starting out of a given node
GRAPH_OUT_OF_NODE_QUERY = '''
  prefix x: <urn:ex:>
  construct {{ ?s ?p ?o }}
  where {{ <{node_uri}> (x:|!x:)* ?s . ?s ?p ?o . }}'''

# Get the Required Credentials for a given Resource_URI and ACL Access mode
REQUIRED_CREDENTIALS_QUERY = '''
  prefix acl: <http://www.w3.org/ns/auth/acl#>
  prefix aifb: <http://aifb.example.org/>
  SELECT ?cred
  WHERE {{
    ?auth a acl:Authorization .
    ?auth acl:accessTo <{resource_url}> .
    ?auth acl:mode {acl_access_mode} .
    ?auth aifb:requiredCredential ?cred
  }}'''
