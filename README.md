# gfc (go file crypt) 
gfc is my first programming project, written the first day I learned Go. I intend to learn Go from its development, so expect some bad code.

Users can use gfc to encrypt archives before sending it to remote backup locations (i.e. cloud storage), which is my use case. Because gfc now supports asymmetric encryption, users can also exchange files safely with RSA-encrypted AES key files. Users can also use hexadecimal or Base64 mode to exchange secret messages easily (e.g. copying [WireGuard](/blog/2020/wireguard/) keys over Facebook messenger).

## Features

- AES256-GCM and AES256-CTR encryption/decryption

- RSA-OEAP SHA512 encryption/decryption

- PBKDF2 passphrase hash derivation

- Hexadecimal or Base64 output

- Reads from files or stdin, and writes to files or stdout

The AES part of the code was first copied from [this source](https://levelup.gitconnected.com/a-short-guide-to-encryption-using-go-da97c928259f) for AES CTR, and [this source](https://gist.github.com/enyachoke/5c60f5eebed693d9b4bacddcad693b47) for AES GCM, although both files have changed so much since.

> ALERT: gfc stable just merged with commits that changed how final file layout is written, so if you have files encrypted with previous build of `gfc`, decrypt it with older versions, and re-encrypt plaintext with the current version.

## Depedencies
I try my best to keep dependencies low and aviod using external libraries. All of the packages required by gfc is from `golang.org/x`.

- `"golang.org/x/term"`

required for a proper, secure passphrase prompt

- `"golang.org/x/crypto"`

required for [AES 256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption

- `"golang.org/x/crypto/pbkdf2"`

required for [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) key derivation function for passphrase

## Building gfc
Build `gfc` executable from source with `go build`:

    $ go build;

The source can also be run with `go run`:

    $ go run main.go -i infile.pdf -o outfile.bin;

## gfc encryption keys
### AES encryptions

> By default, gfc uses passphrases

Every gfc AES encryption uses a 256 bit key which is (by default) derived from user-supplied passphrase, or read directly from a file (with `-k [-f <keyfile>]` switch). The default path for AES key file is `files/aes.key`.

The AES key file should be random and **must be exactly 32 bytes** (passphrase can get longer than that though).

#### Generating AES keys for gfc
To generate a new AES key, I usually use `dd(1)` write 32 bytes of random character to a file:

    $ dd if=/dev/random of=files/key.key bs=32 count=1;

I'm too lazy to add deterministic keyfile hasher, so gfc will assume that the key is well randomized and can be used right away without PBKDF2 or SHA256 hash.

> In any cases, users should replace the test file `gfc/files/aes.key` included in this repository.

### RSA_OEAP SHA512 encryption

Users have 2 ways to provide RSA keys to gfc, with files or with environment variables. For example, if your public key is at `files/pub.pem`, then your command-line will look like this:

    $ gfc -rsa -pub files/pub.pem -i /tmp/myAesKey.key -o /tmp/myAesKey.out;

Or

    $ RSA_PUB_KEY=$(< files/pub.pem) gfc -rsa -i /tmp/myAesKey.key -o /tmp/myAesKey.out;

The same is true for decryption:

    $ gfc -rsa -d -pri files/pri.pem -i /tmp/myAesKey.out -o /tmp/myAesKey;
Or

    $ RSA_PRI_KEY=$(< files/pri.pem) gfc -rsa -d -i /tmp/myAesKey.out -o /tmp/myAesKey;

#### Generating RSA key pair for gfc with OpenSSL

First, you create a private key. In this case, it will be 4096-byte long with name `pri.pem`:

    $ openssl genrsa -out pri.pem 4096

Then, derive a public key `pub.pem` from your private key `pri.pem`:

    $ openssl rsa -in pri.pem -outform PEM -pubout -out pub.pem

## PBKDF2 key derivation function

Passphrases will be securely hashed using PBKDF2, which added random number *salt* to the passphrase before SHA256 hashing is performed to ensure that the derived key will always be unique, even if the same passphrase is reused.

To decrypt files encrypted with key derived from a passphrase, that same *salt* is needed in order to convert input passphrase into the key used to encrypt it in the first place.

Key and salt handling is in `gfc/crypt/key.go`.

## Usage
### Command-line flags
gfc uses Go `flag` package to handle command-line argument. With `flag` packages, some of the flags are mapped to boolean (to toggle between mode, etc), and some are mapped to string variables. These flags can be easily changed in `main()`.

	-d bool
		Decrypt
	-rsa bool
		Use RSA encryption
    -k bool
		Use key file for AES
	-H bool
		Hexadecimal output (encrypt)
		or input (decrypt)
	-B bool
		Base64 output (encrypt)
		or input (decrypt)
	-stdin bool
		Get input from stdin
	-stdout bool
		Direct output to stdout

	-m string
		AES modes, either GCM or CTR
		(default GCM)
	-f string
		AES key file
		(default "files/key.key")
	-pub string
		RSA public key file
		(default "")
	-pri string
		RSA private key file
		(default "")
	-i string
		Input file
		(default "")
    -o string
		Output file
		(default "/tmp/delete.me")

### Default values
These values are mainly for testing purposes

- Input filename > `files/plain`

- Output filename > `/tmp/delete.me`

- Encryption/Decryption mode > AES256-GCM with passphrase

- AES key file filename > `files/key.key`

- RSA key file filename > None, users must supply the file names, or with environment variable `$RSA_PUB_KEY` and `$RSA_PRI_KEY`

### Command examples
`[-i <infile> -o <outfile>]` Specify input filename `secret.txt`, and output filename `secret.bin`. If `-i` or `-o` is omitted, default input filename and output filename will be used:

    $ gfc -i secret.txt -o secret.bin;

`-d` Decrypt

	$ gfc -d -i secret.bin -o secret.txt;

`-H` Encode output in hexadecimal

    $ gfc -H -i ~/Pictures/myNude.jpg -o /tmp/someNude.hex;
	$ gfc -H -d -i ~/someNude.hex -o ~/Pictures/myNude.jpg;

`-B` Encode output in Base64

    $ gfc -B -i ~/Pictures/myNude.jpg -o /tmp/someNude.hex;
	$ gfc -B -d -i ~/someNude.hex -o ~/Pictures/myNude.jpg;

`-stdin` Get input from stdin instead of reading from input file

    $ gfc -stdin

`-stdout` Write output to stdout instead of file, this time with Base64 encoding:

    $ gfc -i secret.txt -stdout -B;

You can combine `-stdin` and `stdout` like so:

    $ gfc -stdin -stdout -B
    this is a secret message
    Passphrase (will not echo)
    ez9vPEPNhA1ZGUuV3vlGvJU3HVoclRMgunaf

    $ gfc -d -stdin -stdout -B
    ez9vPEPNhA1ZGUuV3vlGvJU3HVoclRMgunaf
    Passphrase (will not echo)
    this is a secret message

`-m <mode>` Use AES256-CTR for encryption:

	$ gfc -m ctr -i secret.txt;

`-rsa` Use RSA encryption, with public key file `files/pub.pem`:

    $ RSA_PUB_KEY=$(< files/pub.pem) gfc -rsa -i mySecretAesKey.key -o encryptedKey;

`-rsa -d` Use RSA decryption, with private key file `files/pri.pem`:

    $ RSA_PRIV_KEY=$(< files/pri.pem) gfc -rsa -i encryptedKey -o mySecreyAesKey.key;

`-k` Use key file to encrypt or decrypt. If `-f <keyfilename>` is not given, the keyfile filename defaults to `${pwd}/files/key.key`.

    $ gfc -k -i secret.txt -o secret.bin;
    $ gfc -k -i secret.bin -o test.txt -d;

`-k -f <key file>` Use key file to encrypt and decrypt:

	$ gfc -m ctr -k -f ~/mykey.key -i secret.txt -o secret.bin;
	$ gfc -m ctr -d -k -f ~/mykey.key -i secret.bin -o secret.out;

All the commands above will produce encrypted binary files. If you want your file encrypted into hex string, use `-H` flag instead, though this is not recommended because of larger file size.

## Encrypting a directory

> Bash script `rgfc.sh` can be used to perform this task. Usage is simple; `$ rgfc.sh <dir>` will first create temporary tarball from `<dir>`, and encrpyts the tarball. If the encryption is successful, the unencrypted tarball is removed.

gfc does not recursively encrypt/decrypt files - that would add needless complexity. If you are encrypting a directory (folder), use `tar(1)` to archive (and optionally compress) the directory, and use gfc to encrypt that tarball.

For example, to create Zstd compressed archive of directory *before encryption* `foo`:

    $ tar --zstd -cf foo.zstd foo;

And extract it after decryption with:
    
	$ tar --zstd -xf foo.zstd;

Or with xz compression:

    $ tar -cJf foo.txz foo;
    $ tar -xJf foo.txz;

## Testing gfc
I wrote gfc before I learned about TDD, so no unit tests are written for gfc. However, a Bash script `test.sh` is shipped with gfc and can be use to test a combination of commands.

## Known issues

- Memory usage

Due to how gfc uses encryption and converison buffers, gfc can use large chunks of memory when encrypting and decrypting large files, and even more so when converting to and from hexadecimals.

- Bad error detection

Other than the standard `"flag"` package, gfc does not have any command-line error checking built-in, so if you enter the command incorrectly, gfc may fail silently.

For now, gfc's exit status of `1` indicate user error (e.g. files unreadable/unwritable, or key file is too small), while `2` indicates internal error. Cryptography failures will cause panic.

- Unstable spec

## Repositories
There are 2 repositories for gfc, one on GitHub.com and one on GitLab.com

The main (stable) branch of gfc is hosted on [Github](https://github.com/artnoi43/gfc), while the development branch is hosted on [GitLab](https://gitlab.com/artnoi/gfc)

## License
This code is Free to use, i.e. as with BSD licensed software.
