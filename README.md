# The Matchmaking Encryption Bulletin Board

This repository holds a prototype implementation of a bulletin board hidden service that uses an Identity-Based Matchmaking Encryption (IB-ME) scheme. It allows clients to exchange data over the Tor network in an anonymous way, while having strong guarantees about the identities of both receivers and senders. In a nutshell, the bulletin board is composed by two parts: A web server implemented as Tor hidden service and, a command line client that permits to upload and download data from the server.

A user that wants to post a message to the bulletin board can use the command line to encrypt it (using their IB-ME encryption key and an identity string policy for the intended receiver), and upload the ciphertext on the web server using the Tor network. These ciphertexts are available to anyone.

A receiver can now use the client to download all the ciphertexts and try to decrypt each one, using the receiver's decryption key and the sender's identity policy. The client will report to the user the outcome of the decryption phase, showing all the successfully decrypted messages.

You can use the client application to play with the running service in [http://bjopwtc2f3umlark.onion/](http://bjopwtc2f3umlark.onion/). We created a key file so you can use the encryption and decryption keys of identities "alice", "bob", "charlie", and "zelda". We have the keys for identity "authors", not included in the key file. There is a message from us for each identity. Please, leave us a message too!

## Client application

### Dependencies

The client application is built with Python 3.6 and depends on [Charm Crypto](https://jhuisi.github.io/charm/index.html) and the `click` and `requests` libraries. It also requires Tor.

For installing Charm Crypto, follow [these instructions](https://jhuisi.github.io/charm/install_source.html).

For `click` and `requests`, you can install them using `pip`:

    pip install click
    pip install requests

### Usage

    $ python3 client.py --help
    Usage: client.py [OPTIONS] COMMAND [ARGS]...

    Options:
      -u, --url TEXT   URL of the bulletin board
      -l, --localhost  Look for the bulletin board in http://localhost:5000
      --help           Show this message and exit.

    Commands:
      peek  Takes a gander at the bulletin board, without decrypting
      post  Posts an encrypted message to the bulletin board
      read  Reads encrypted messages from the bulletin board

## Server

### Dependencies

The server depends on the `flask` and `flask_restful` libraries.

For `flask` and `flask_restful`, you can install them using `pip`:

    pip install flask
    pip install flask_restful

### Usage

    $ python3 api.py