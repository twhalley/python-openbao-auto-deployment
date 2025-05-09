import os
import ssl
import json
from http.client import HTTPSConnection
from pathlib import Path

# Get environment variables
BAO_ADDR = os.getenv('BAO_ADDR', 'https://127.0.0.1:8200')
#BAO_TOKEN = os.getenv('BAO_TOKEN')

# Path to your CA bundle file if you're using a self-signed certificate
CA_BUNDLE_PATH = 'openbao/openbao_ssl/selfsigned.crt'

# Ensure tokens are available
# if not BAO_TOKEN or not GITHUB_TOKEN:
#     raise ValueError("BAO_TOKEN and GITHUB_TOKEN must be set")

def create_ssl_context(verify_ssl=True):
    context = ssl.create_default_context()
    if verify_ssl:
        context.load_verify_locations(CA_BUNDLE_PATH)
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context

def make_request(method, path, data=None, headers=None, verify_ssl=True):
    host = BAO_ADDR.split('://')[1].split(':')[0]
    port = int(BAO_ADDR.split(':')[-1])
    
    context = create_ssl_context(verify_ssl)
    conn = HTTPSConnection(host, port, context=context)
    
    try:
        if data:
            body = json.dumps(data)
            if headers is None:
                headers = {}
            headers['Content-Type'] = 'application/json'
        else:
            body = None
            
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        response_data = response.read().decode()
        
        if response.status >= 400:
            raise Exception(f"HTTP Error {response.status}: {response_data}")
            
        return json.loads(response_data) if response_data else None
    finally:
        conn.close()

# Initialize openBAO
def initialize_openbao(verify_ssl=True): # Enable to true prod
    try:
        init_data = make_request(
            'POST',
            '/v1/sys/init',
            data={
                "secret_shares": 1,
                "secret_threshold": 1
            },
            verify_ssl=verify_ssl
        )

        unseal_key = init_data['keys'][0]
        root_token = init_data['root_token']

        print("Unseal Key:", unseal_key)
        print("Root Token:", root_token)

        result = {
            "unseal_key": unseal_key,
            "root_token": root_token
        }

        return result
    except ssl.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

def unseal_vault(verify_ssl=True, unseal_key=str):
    try:
        unseal_data = make_request(
            'POST',
            '/v1/sys/unseal',
            data={
                "key": unseal_key
            },
            verify_ssl=verify_ssl
        )

        if unseal_data['sealed'] == False:
            print("OpenBAO is successfully unsealed.")
        else:
            print("OpenBAO is still sealed. Additional unseal keys may be required.")

    except ssl.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

def create_policies(verify_ssl=True, root_token=str, service=str):
    headers = {
        'X-Vault-Token': root_token
    }
    
    try:
        # Create a policy for Jenkins
        policy = f'''
            path "database/creds/{service}-role" {{
            capabilities = ["read"]
            }}
        '''

        response = make_request(
            'PUT',
            f'/v1/sys/policies/acl/{service}-policy',
            data={
                'policy': policy
            },
            headers=headers,
            verify_ssl=verify_ssl
        )
        print(f"Policy creation status: {response}")

    except ssl.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

def enable_approle(verify_ssl=True, root_token=str, service=str):
    headers = {
        'X-Vault-Token': root_token
    }
    
    try:
        # Enable AppRole auth method
        approle_auth = make_request(
            'POST',
            '/v1/sys/auth/approle',
            data={
                'type': 'approle'
            },
            headers=headers,
            verify_ssl=verify_ssl
        )
        print(approle_auth)
        print('Approle Status Code: Success')

        # Create an AppRole for Jenkins
        role_data = {
            'policies': f'{service}-policy',
            'token_ttl': '1h',
            'token_max_ttl': '4h'
        }
        approle_jenkins = make_request(
            'POST',
            f'/v1/auth/approle/role/{service}',
            data=role_data,
            headers=headers,
            verify_ssl=verify_ssl
        )
        
        print(approle_jenkins)
        print('Approle jenkins Status Code: Success')
    except ssl.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

# Fetch RoleID and SecretID for Jenkins:
def fetch_role_id_and_secret_id(verify_ssl=True, root_token=str, service=str):
    headers = {
        'X-Vault-Token': root_token
    }

    try:
        role_id_response = make_request(
            'GET',
            f'/v1/auth/approle/role/{service}/role-id',
            headers=headers,
            verify_ssl=verify_ssl
        )
        
        role_id = role_id_response['data']['role_id']

        secret_id_response = make_request(
            'POST',
            f'/v1/auth/approle/role/{service}/secret-id',
            headers=headers,
            verify_ssl=verify_ssl
        )

        secret_id = secret_id_response['data']['secret_id']

        print(f"Role ID for {service}:  {role_id}")
        print(f"Secret ID for {service}: {secret_id}")

    except ssl.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

#  Fetch Jenkins secrets via approle
def enable_database_engine(verify_ssl=True, root_token=str, service=str):
    
    headers = {
        'X-Vault-Token': root_token
    }

    try:
        # Enable the database secrets engine
        enable_database_engine_response = make_request(
            'POST',
            '/v1/sys/mounts/database',
            data={
                'type': 'database'
            },
            headers=headers,
            verify_ssl=verify_ssl
        )

        # Configure the PostgreSQL secrets engine (replace with your DB details)
        db_config = {
            'plugin_name': 'postgresql-database-plugin',
            'allowed_roles': f'{service}-role',
            'connection_url': 'postgresql://{{username}}:{{password}}@localhost:5432/mydatabase',
            'username': 'dbadmin',
            'password': 'dbpassword'
        }
        response = make_request(
            'POST',
            '/v1/database/config/my-postgresql-db',
            data=db_config,
            headers=headers,
            verify_ssl=verify_ssl
        )

        # Create a role for the PostgreSQL secrets engine
        db_role = {
            'db_name': 'my-postgresql-db',
            'creation_statements': 'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD "{{password}}" VALID UNTIL "{{expiration}}";',
            'default_ttl': '1h',
            'max_ttl': '24h'
        }
        make_request(
            'POST',
            f'/v1/database/roles/{service}-role',
            data=db_role,
            headers=headers,
            verify_ssl=verify_ssl
        )
    except ssl.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

def enable_audit_log(verify_ssl=True, root_token=str, approle=str):
    pass

if __name__ == '__main__':
    # Call the function to initialize OpenBAO with SSL verification enabled
    try:
        init = initialize_openbao(True)
        print(init)
        unseal_key = init['unseal_key']
        root_token = init['root_token']
    except TypeError:
        print('TypeError, has OpenBAO already been setup?')
    try:
        unseal_vault(True, unseal_key)
    except NameError:
        print('Name error, unseal key not defined.')
    try:
        create_policies(True, root_token, 'jenkins')
        enable_approle(True, root_token, 'jenkins')
        
    except NameError:
        print('Root token is not defined.')