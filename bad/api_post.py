from pathlib import Path
import tempfile
import os

import click
import requests

# Use secure temporary directory with restricted permissions
# tempfile.gettempdir() returns the appropriate temp directory for the platform
# We create a subdirectory with secure permissions to store the API key
temp_dir = Path(tempfile.gettempdir())
secure_dir = temp_dir / '.vulpy_api'

# Create directory with secure permissions (0700 - only owner can access)
if not secure_dir.exists():
    secure_dir.mkdir(mode=0o700, exist_ok=True)
else:
    # Ensure existing directory has secure permissions
    secure_dir.chmod(0o700)

api_key_file = secure_dir / 'api_key.txt'

# Ensure the key file has secure permissions if it exists
if api_key_file.exists():
    api_key_file.chmod(0o600)

@click.command()
@click.argument('message')
def cmd_api_client(message):
    if not api_key_file.exists():

        username = click.prompt('Username')
        password = click.prompt('Password', hide_input=True)

        r = requests.post('http://127.0.1.1:5000/api/key', json={'username':username, 'password':password})

        if r.status_code != 200:
            click.echo('Invalid authentication or other error ocurred. Status code: {}'.format(r.status_code))
            return False


        api_key = r.json()['key']
        print('Received key:', api_key)

        # Create the file with secure permissions (owner read/write only)
        with api_key_file.open('w') as outfile:
            outfile.write(api_key)
        api_key_file.chmod(0o600)

    api_key = api_key_file.open().read()
    r = requests.post('http://127.0.1.1:5000/api/post', json={'text':message}, headers={'X-APIKEY': api_key})
    print(r.text)


if __name__ == '__main__':
    cmd_api_client()
