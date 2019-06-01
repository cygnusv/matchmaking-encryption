from ibme import IBME
import requests
import base64
import click
import json
import binascii

keys = json.load(open('keys.json'))

ME = IBME()
master_public_key = ME.deserialize_tuple(base64.urlsafe_b64decode(keys["public_key"]))
del keys["public_key"]

api = "http://bjopwtc2f3umlark.onion"

def get_session():
    session = requests.session()
    if ".onion" in api:
        session.proxies = {'http':  'socks5h://127.0.0.1:9050',
                           'https': 'socks5h://127.0.0.1:9050'}
    return session

def crc(data):
    return binascii.crc_hqx(data, 0).to_bytes(2, 'big')

@click.group()
@click.option('--url', '-u', help="URL of the bulletin board")
@click.option('--localhost', '-l', is_flag=True, help="Look for the bulletin board in http://localhost:5000")
def cli(url, localhost):
    global api
    if localhost:
        api = "http://localhost:5000"
    if url:
        api = url
        print(f"Using url {api}")

@click.command(help="Posts an encrypted message to the bulletin board")
@click.option('--receiver', prompt="Receiver's policy string", help="Receiver's policy string")
@click.option('--sender', prompt="Sender's encryption key", help="Sender's encryption key")
@click.option('--message', prompt="Message to send", help="Message to send")
def post(receiver, sender, message):
    ek = ME.deserialize_tuple(base64.urlsafe_b64decode(keys[sender]["ek"]))[0]
    
    message = message.encode()
    padded_message = crc(message) + message
    ciphertext = ME.encrypt(master_public_key, receiver, ek, padded_message)
    ctxt = ME.serialize_ciphertext(ciphertext)
    b64_ctxt = base64.urlsafe_b64encode(ctxt)
    click.echo(b"Ciphertext: " + b64_ctxt)

    res = get_session().put(f'{api}/messages', data={'message': b64_ctxt}).json()
    click.echo(f"Index of the message: {res}")

@click.command(help="Takes a gander at the bulletin board, without decrypting")
def peek():
    res = get_session().get(f'{api}/messages').json()
    for i, message in enumerate(res):
        click.echo(f"({i}): {message}")

def decrypt_ciphertext(dk, ctxt, sender):
    ctxt = base64.urlsafe_b64decode(ctxt)
    ctxt = ME.deserialize_ciphertext(ctxt)
    padded_message = ME.decrypt(master_public_key, dk, sender, ctxt)
    pad, message = padded_message[:2], padded_message[2:]
    return message if crc(message) == pad else None

@click.command(help="Reads encrypted messages from the bulletin board")
@click.option('--receiver', prompt="Receiver's policy string", help="Receiver's policy string")
@click.option('--sender', prompt="Sender's attribute string", help="Sender's attribute string")
def read(receiver, sender):
    dk = ME.deserialize_tuple(base64.urlsafe_b64decode(keys[receiver]["dk"]))
    ciphertexts = get_session().get(f'{api}/messages').json()

    for i, ciphertext in enumerate(ciphertexts):
        message = decrypt_ciphertext(dk, ciphertext, sender)
        if message:
            click.echo(f"{i}: {message.decode('utf-8')}")


cli.add_command(post)
cli.add_command(peek)
cli.add_command(read)

if __name__ == '__main__':
    cli()

