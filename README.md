This is a simple tool to recover your password from a Claws configuration file.

# Usage

First off, just say `make` to compile the program.
You will probably need `libglib2.0-dev` and `libgnutls28-dev` for that.

Then, look up two important values:

 * `master_passphrase_salt` from the `.claws-mail/clawsrc` file and
 * all the scrambled passwords from the `.claws-mail/passwordstorerc` file.

Now you can call the program:
`./clawspeek SALT PASSWORD [...]`
Note that the you have to put the password in single quotes since it begins with a brace.

It extracts your plaintext passwords and writes them to the command line, nothing else. I promise.

Note that the Master Passphrase feature is not supported by this program, as I did not need it myself.
You can simply feed it as the second parameter to `password_decrypt`, or fix this program and send me a pull request.

# Motivation

There are already two tools for extracting passwords from Claws: [mones/clawspeek](https://github.com/mones/clawspeek) and [b4n/clawsmail-password-decrypter](https://github.com/b4n/clawsmail-password-decrypter).
Unfortunately for them, Claws has changed the method for password scrambling in 2016, and neither of these programs have been updated.

I could not bear the disgrace of resetting my mail password, so I copied the parts of Claws source code that are relevant to password decryption, and added a tiny `main` function.
