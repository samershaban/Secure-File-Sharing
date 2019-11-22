# Cryptr
Encrypt and Decrypt any file for secure file sharing across the internet. Tested with .txt .png .gif and .mp4. An example is given in the PDF file.


----------
Compile with: `$ javac Cryptr.java`

1. Generating a secret key
	```
	$ java Cryptr generatekey <secret key file>
	```
2. Encrypting a file using a secret key
	```
	$ java Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>
	```	
3. Generate Key Pair
	```
	$ openssl genrsa -out <private key name>.pem 2048
	$ openssl pkcs8 -topk8 -inform PEM -outform DER -in <private key name>.pem -out <private key name 2>.der -nocrypt
	$ openssl rsa -in <private key name>.pem -pubout -outform DER -out <public key name>.der
	```
4. Encrypting a secret key using a public key
	```
	$ java Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file>
	```
5. Decrypting a secret key using a private key
	```
	$ java Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>
	```
6. Decrypting a file using a secret key
	```
	$ java Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>
	```
		
	
	
-----------------
- Class project for Rutgers University's Computer Security class
