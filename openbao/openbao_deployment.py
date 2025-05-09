import os
import requests
from pathlib import Path

# Get environment variables
BAO_ADDR = os.getenv('BAO_ADDR', 'https://127.0.0.1:8200')
#BAO_TOKEN = os.getenv('BAO_TOKEN')

# Path to your CA bundle file if you're using a self-signed certificate
CA_BUNDLE_PATH = 'openbao/openbao_ssl/selfsigned.crt'

# Ensure tokens are available
# if not BAO_TOKEN or not GITHUB_TOKEN:
#     raise ValueError("BAO_TOKEN and GITHUB_TOKEN must be set")

# Initialize openBAO
def initialize_openbao(verify_ssl=True): # Enable to true prod
    try:
        # Make the request with SSL verification
        init_response = requests.post(
            f"{BAO_ADDR}/v1/sys/init",
            json={
                "secret_shares": 1,
                "secret_threshold": 1
            },
            verify=CA_BUNDLE_PATH if verify_ssl else False  # Ensure SSL verification
        )

        #init_response.raise_for_status()  # Raise an exception for HTTP errors
        init_data = init_response.json()

        unseal_key = init_data['keys'][0]
        root_token = init_data['root_token']

        print("Unseal Key:", unseal_key)
        print("Root Token:", root_token)

        result = {
            "unseal_key": unseal_key,
            "root_token": root_token
        }

        return result
    except requests.exceptions.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")

def unseal_vault(verify_ssl=True, unseal_key=str):
    try:
        # Send the unseal request
        unseal_response = requests.post(
            f"{BAO_ADDR}/v1/sys/unseal",
            json={
                "key": unseal_key
            },
            verify=CA_BUNDLE_PATH if verify_ssl else False # Ensure SSL verification
        )

        unseal_response.raise_for_status()  # Raise an exception for HTTP errors
        unseal_data = unseal_response.json()

        if unseal_data['sealed'] == False:
            print("OpenBAO is successfully unsealed.")
        else:
            print("OpenBAO is still sealed. Additional unseal keys may be required.")

    except requests.exceptions.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")

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

        jenkins_policy_request = requests.put(f'{BAO_ADDR}/v1/sys/policies/acl/{service}-policy',
                                                json={
                                                    'policy': policy
                                                },
                                                headers=headers,
                                                verify=CA_BUNDLE_PATH if verify_ssl else False)
        print(jenkins_policy_request.status_code)

    except requests.exceptions.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")

def enable_approle(verify_ssl=True, root_token=str, service=str):
    headers = {
        'X-Vault-Token': root_token
    }
    
    try:
        # Enable AppRole auth method
        approle_auth = requests.post(f'{BAO_ADDR}/v1/sys/auth/approle',
                                        json={
                                            'type': 'approle'
                                        },
                                        headers=headers,
                                        verify=CA_BUNDLE_PATH if verify_ssl else False)
        print(approle_auth.text)
        print('Approle Status Code %s ' % (approle_auth.status_code))
        # Create an AppRole for Jenkins
        role_data = {
            'policies': f'{service}-policy',
            'token_ttl': '1h',
            'token_max_ttl': '4h'
        }
        approle_jenkins = requests.post(f'{BAO_ADDR}/v1/auth/approle/role/{service}', headers=headers, json=role_data, verify=CA_BUNDLE_PATH if verify_ssl else False)
        
        print(approle_jenkins.text)
        print('Approle jenkins Status Code %s ' % (approle_jenkins.status_code))
    except requests.exceptions.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")

# Fetch RoleID and SecretID for Jenkins:
def fetch_role_id_and_secret_id(verify_ssl=True, root_token=str, service=str):
    headers = {
        'X-Vault-Token': root_token
    }

    try:
        role_id_response = requests.get(f'{BAO_ADDR}/v1/auth/approle/role/{service}/role-id',
                                        headers=headers,
                                        verify=CA_BUNDLE_PATH if verify_ssl else False
                                        )
        
        role_id = role_id_response.json()['data']['role_id']

        secret_id_response = requests.post(f'{BAO_ADDR}/v1/auth/approle/role/{service}/secret-id',
                                        headers=headers,
                                        verify=CA_BUNDLE_PATH if verify_ssl else False
                                        )

        secret_id = secret_id_response.json()['data']['secret_id']

        print(f"Role ID for {service}:  {role_id}")
        print(f"Secret ID for {service}: {secret_id}")

    except requests.exceptions.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")

#  Fetch Jenkins secrets via approle
def enable_database_engine(verify_ssl=True, root_token=str, approle=str):
    
    headers = {
        'X-Vault-Token': root_token
    }

    try:
        # Enable the database secrets engine
        enable_database_engine_response = requests.post(f'{BAO_ADDR}/v1/sys/mounts/database',
                        headers=headers,
                        json={
                            'type': 'database'
                        },
                        verify=CA_BUNDLE_PATH if verify_ssl else False)

        # Configure the PostgreSQL secrets engine (replace with your DB details)
        db_config = {
            'plugin_name': 'postgresql-database-plugin',
            'allowed_roles': f'{service}-role',
            'connection_url': 'postgresql://{{username}}:{{password}}@localhost:5432/mydatabase',
            'username': 'dbadmin',
            'password': 'dbpassword'
        }
        response = requests.post(f'{BAO_ADDR}/v1/database/config/my-postgresql-db',
                        headers=headers,
                        json=db_config,
                        verify=CA_BUNDLE_PATH if verify_ssl else False)

        # Create a role for the PostgreSQL secrets engine
        db_role = {
            'db_name': 'my-postgresql-db',
            'creation_statements': 'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD "{{password}}" VALID UNTIL "{{expiration}}";',
            'default_ttl': '1h',
            'max_ttl': '24h'
        }
        requests.post(f'{VAULT_ADDR}/v1/database/roles/{service}-role',
                        headers=headers,
                        json=db_role,
                        verify=CA_BUNDLE_PATH if verify_ssl else False)
    except requests.exceptions.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")

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
        
        # fetch_role_id_and_secret_id(True, 's.kxpMtsPlAKPWHlY8Gsv3gGON', 'jenkins')
        # enable_database_engine(True, 's.kxpMtsPlAKPWHlY8Gsv3gGON', 'jenkins')
    except NameError:
        print('Root token is not defined.')