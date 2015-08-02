# Teneo

Regenerable ed25519 keys for OpenSSH.

Teneo allows you to deterministically generate an ed25519 key pair for OpenSSH.
This allows you to (re)create your key pair on a computer which lacks
persistent storage. You must be able to remember three things to generate a
key: a user defined "username", a Teneo defined "profile" and your passphrase.

## Usage

    Usage: ./teneo [ options ] [ output directory ]

    Help Options:
      -h, --help                Show help options

    Key Options:
      -u, --user <username>     Specify which username to use
      -p, --profile <profile>   Specify which profile to use

      Available Profiles:
          2015v1

    Output Format Options:
      -s, --openssh             Output OpenSSH public and private key

## Example Usage

1. We start by creating a key pair for OpenSSH using "ahf@teneo.0x90.dk@ as username.

        $ ./teneo --openssh --user ahf@teneo.0x90.dk
        Passphrase: foobar
        Generating key pair using the '2015v1' profile ...
        This may take a little while ...
        Succesfully generated key pair ...
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
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICthH3UNgcsJ5hv4uzfDJixImsAOzu2ik5KWKhnoY1fY ahf@teneo.0x90.dk

        $ openssl sha256 id_ed25519.pub
        SHA256(id_ed25519.pub)= a394eb08102eefb020d3274285671d113604690bedb551c5dfbf27c0d6844482

2. Wipe the key pair.

        $ rm -rf id_ed25519
        $ rm -rf id_ed25519.pub

3. Create the key again using the same parameters and passphrase.

        $ ./teneo --openssh --user ahf@teneo.0x90.dk
        Passphrase: foobar
        Generating key pair using the '2015v1' profile ...
        This may take a little while ...
        Succesfully generated key pair ...
        Saving OpenSSH secret key to id_ed25519 ...
        Saving OpenSSH public key to id_ed25519.pub ...

        $ openssl sha256 id_ed25519.pub
        SHA256(id_ed25519.pub)= a394eb08102eefb020d3274285671d113604690bedb551c5dfbf27c0d6844482

## Authors

- [Alexander Færøy](https://twitter.com/ahfaeroey) ([ahf@0x90.dk](mailto:ahf@0x90.dk)).

## Todo

1. Code clean-up. This is a prototype written during two evenings of a weekend.
2. GnuPG format support.
3. Consider the new Tor ed25519 ID keys?
4. Add proper tests. Use Travis CI to build on both OS X and Linux.

## License

    Copyright (c) 2015 Alexander Færøy.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
