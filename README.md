# final
Cryptography and Network Security - Final Project

Dependencies:
- Stack (https://docs.haskellstack.org/en/stable/README/)

To compile, simply enter this repository and run

    stack build --copy-bins --local-bin-path=.

This will create a binary file called `final`.
Running

    ./final --help

will provide information about each option and command. The most relevant
commands are given here:
 - to run the server: `./final server`
 - to run the client: `./final client`