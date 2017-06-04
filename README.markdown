# Passphrase-identity

Regenerable ed25519 keys for OpenSSH and OpenPGP.

Passphrase-identity allows you to deterministically generate ed25519 key pairs (signing keys) for OpenSSH and OpenPGP from a set of parameters.
This allows you to (re)generate your key pair on a computer which, for example, lacks persistent storage - it derives an "identity" from a passphrase.

You must be able to remember three things to (re)generate your key pair;

1. A user defined "username", which can be any string.
2. A Passphrase-identity defined "profile" name. There's currently only two profiles available: `2015v1`, and `2017`, both of which use `scrypt()` + `salsa20/8` + `sha256` as KDF.
3. Your personally selected passphrase.

## Usage

    Usage: ./passphrase-identity [ options ] [ output directory ]

    Help Options:
      -h, --help                Display this message (default behavior)

    Key Options:
      -u, --user <username>     Specify which username to use [as salt]
      -p, --profile <profile>   Specify which profile to use

      Available Profiles:

          2015v1
          2017

    Output Format Options:

      -s, --openssh             Output OpenSSH public and private key
                                The keys are written to id_ed25519{,.pub}

      -g, --gpg                 Output OpenPGP public and private key
                                The keys are written to {public,private}.asc

## Example Usage

1. We start by creating a key pair for OpenSSH using `ahf@passphrase-identity.0x90.dk` as username.

        $ ./passphrase-identity --openssh --user ahf@passphrase-identity.0x90.dk
        Passphrase: foobar
        Generating key pair using the '2015v1' profile ...
        This may take a little while ...
        Successfully generated key pair ...
        Saving OpenSSH secret key to id_ed25519 ...
        Saving OpenSSH public key to id_ed25519.pub ...

        $ cat id_ed25519
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACArYR91DYHLCeYb+Ls3wyYsSJrADs7topOSlioZ6GNX2AAAAJj36teu9+rX
        rgAAAAtzc2gtZWQyNTUxOQAAACArYR91DYHLCeYb+Ls3wyYsSJrADs7topOSlioZ6GNX2A
        AAAEAv/A/ak2U1vqbQR7sDFmJFp1eC7kv0HdZYm4Dt50n33ythH3UNgcsJ5hv4uzfDJixI
        msAOzu2ik5KWKhnoY1fYAAAAEWFoZkB0ZW5lby4weDkwLmRrAQIDBA==
        -----END OPENSSH PRIVATE KEY-----

        $ cat id_ed25519.pub
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICthH3UNgcsJ5hv4uzfDJixImsAOzu2ik5KWKhnoY1fY ahf@passphrase-identity.0x90.dk

        $ openssl sha256 id_ed25519.pub
        SHA256(id_ed25519.pub)= a394eb08102eefb020d3274285671d113604690bedb551c5dfbf27c0d6844482

2. Wipe the key pair.

        $ shred -u id_ed25519
        $ shred -u id_ed25519.pub

3. Create the key again using the same parameters and passphrase.

        $ ./passphrase-identity --openssh --user ahf@passphrase-identity.0x90.dk
        Passphrase: foobar
        Generating key pair using the '2015v1' profile ...
        This may take a little while ...
        Successfully generated key pair ...
        Saving OpenSSH secret key to id_ed25519 ...
        Saving OpenSSH public key to id_ed25519.pub ...

        $ openssl sha256 id_ed25519.pub
        SHA256(id_ed25519.pub)= a394eb08102eefb020d3274285671d113604690bedb551c5dfbf27c0d6844482

## Compiling on Ubuntu

```bash
# if you want to use a proxy for git via https:
# git config --global http.proxy 'socks5://127.0.0.1:9150'

git clone https://github.com/ahf/passphrase-identity
apt-get install autoconf libtool pkg-config libsodium-dev -y
cd passphrase-identity/
./autogen.sh
./configure
make
# Binary will be named ./src/passphrase-identity
```

## Authors

- [Alexander Færøy](https://twitter.com/ahfaeroey) ([ahf@0x90.dk](mailto:ahf@0x90.dk)).

## Todo

1. Code clean-up. This is a prototype written during two evenings of a weekend.
2. Consider the new Tor ed25519 ID keys?
3. Add proper tests. Use Travis CI to build on both OS X and Linux.
4. Add fancy graphics after key generation, like the OpenSSH client, such that
   the user can quickly identify if something is wrong. 
5. Add cracklib support and remember to make it possible to disable it as well.

## License

See the LICENSE file.
