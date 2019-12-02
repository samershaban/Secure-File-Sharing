import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.Base64;
import java.util.Arrays;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

/*
 *               Cryptr
 * By Samer Shaban and Omar Atieh
 *
 * Cryptr is a java encryption toolset
 * that can be used to encrypt/decrypt files
 * and keys locally, allowing for files to be
 * shared securely over the world wide web
 *
 * Cryptr provides the following functions:
 *	 1. Generating a secret key
 *   2. Encrypting a file with a secret key
 *   3. Decrypting a file with a secret key
 *   4. Encrypting a secret key with a public key
 *   5. Decrypting a secret key with a private key
 *
 */

public class Cryptr2 {



	/**
	 * Generates an 128-bit AES secret key and writes it to a file
	 *
	 * @param secKeyFile name of file to store secret key
	 */
	static void generateKey(String secKeyFile) throws Exception {
		// First we need to generate a 128 bit bit key for AES
		KeyGenerator generate = KeyGenerator.getInstance("AES");
		generate.init(128);
		SecretKey secretkey = generate.generateKey();

		// Output key to file
		FileOutputStream output = null;
		try {
			output = new FileOutputStream(secKeyFile);
			byte[] keys = secretkey.getEncoded();
			output.write(keys);
			output.close();
		} catch (Exception ex) {
			throw new Exception("Error" + ex.getMessage(), ex);
		}
	}

	/**
	 * Extracts generates an initialization vector, uses
	 * them to encrypt the original file, and writes an encrypted file containing
	 * the initialization vector followed by the encrypted file data
	 *
	 * @param originalFile  name of file to encrypt
	 * @param secKeyFile    name of file storing secret key
	 * @param encryptedFile name of file to write initVector and encrypted file data
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 */

	static void encryptFile(String originalFile, String secKeyFile, String encryptedFile) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
		// need to import the secret key from the file
		byte[] keys = null;
		SecretKeySpec Key = null;
		byte[] initVector = null;
		try {
			keys = Files.readAllBytes(Paths.get(secKeyFile));
			Key = new SecretKeySpec(keys, "AES");
		} catch (IOException e) {
			e.printStackTrace();
		}
		SecureRandom srandom = new SecureRandom();
		// Utilizing an initialization vector
		initVector = new byte[16];
		//utilizing the securerandom srandom function
		srandom.nextBytes(initVector);
		IvParameterSpec ivspec = new IvParameterSpec(initVector);

		// creating the cipher
		String cipherType = "AES/CBC/PKCS5Padding";

		Cipher cipher = Cipher.getInstance(cipherType);
		cipher.init(Cipher.ENCRYPT_MODE, Key, ivspec);




		// Utilizing the File input and output stream to encrypt and output.
		FileInputStream originalStream = null;
		FileOutputStream outputStream = null;
		try {

			originalStream = new FileInputStream(originalFile);
			outputStream = new FileOutputStream(encryptedFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		try {
			outputStream.write(initVector);
			byte[] inbuffer = new byte[1024];
			int temp;
			while ((temp = originalStream.read(inbuffer)) != -1) {
				byte[] outt = cipher.update(inbuffer, 0, temp);
				if (outt != null)
					outputStream.write(outt);
			}
			byte[] outt = cipher.doFinal();
			if (outt != null)
				outputStream.write(outt);
		} catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Extracts the secret key from a file, extracts the initialization vector from
	 * the beginning of the encrypted file, uses both secret key and initialization
	 * vector to decrypt the encrypted file data, and writes it to an output file
	 *
	 * @param encryptedFile name of file storing initVector and encrypted data
	 * @param secKeyFile    name of file storing secret key
	 * @param outputFile    name of file to write decrypted data to
	 */

	static void decryptFile(String encryptedFile, String secKeyFile, String outputFile) {
		//read from the intitiaization vectr and extract it
		FileInputStream initVectorStream = null;
		byte[] initVector = new byte[16];
		try {
			initVectorStream = new FileInputStream(encryptedFile);
			initVectorStream.read(initVector);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}


		// load secret key

		IvParameterSpec ivspec = new IvParameterSpec(initVector);
		byte[] keys;
		SecretKeySpec Key = null;
		try {
			keys = Files.readAllBytes(Paths.get(secKeyFile));
			Key = new SecretKeySpec(keys, "AES");
		} catch (IOException e) {
			e.printStackTrace();
		}

		Cipher cipher = null;
		String cipherType = "AES/CBC/PKCS5Padding";

		try {
			cipher = Cipher.getInstance(cipherType);
			cipher.init(Cipher.DECRYPT_MODE, Key, ivspec);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			e1.printStackTrace();
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e2) {
			e2.printStackTrace();
		}

		// Decrypt
		FileInputStream input = null;
		FileOutputStream decryptStream = null;
		try {
			input = initVectorStream;
			decryptStream = new FileOutputStream(outputFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		byte[] inBuffer = new byte[1024];
		int temp;
		try {
			while ((temp = input.read(inBuffer)) != -1) {
				byte[] outBuffer = cipher.update(inBuffer, 0, temp);
				if (outBuffer != null)
					decryptStream.write(outBuffer);
			}
			byte[] outt = cipher.doFinal();
			if (outt != null)
				decryptStream.write(outt);
		} catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Extracts secret key from a file, encrypts a secret key file using a public
	 * Key (*.der) and writes the encrypted secret key to a file
	 *
	 * @param secKeyFile name of file holding secret key
	 * @param pubKeyFile name of public key file for encryption
	 * @param encKeyFile name of file to write encrypted secret key
	 */
	static void encryptKey(String secKeyFile, String pubKeyFile, String encKeyFile) {

		// getting the rsa key
		PublicKey publicKey = null;
		byte[] rsa = null;
		X509EncodedKeySpec tem = null;
		KeyFactory factoryKey = null;

		try {
			rsa = Files.readAllBytes(Paths.get(pubKeyFile));
			tem = new X509EncodedKeySpec(rsa);
			factoryKey = KeyFactory.getInstance("RSA");
			publicKey = factoryKey.generatePublic(tem);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}

		// load AES secret key
		SecretKeySpec secretkey = null;
		byte[] AESkb = null;
		Cipher cipher = null;
		try {
			AESkb = Files.readAllBytes(Paths.get(secKeyFile));
			secretkey = new SecretKeySpec(AESkb, "AES");
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Initialize Cipher for encryption

		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}

		// Output
		try {
			FileOutputStream out = new FileOutputStream(encKeyFile);
			byte[] tempe = cipher.doFinal(secretkey.getEncoded());
			out.write(tempe);
		} catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Decrypts an encrypted secret key file using a private Key (*.der) and writes
	 * the decrypted secret key to a file
	 *
	 * @param encKeyFile  name of file storing encrypted secret key
	 * @param privKeyFile name of private key file for decryption
	 * @param secKeyFile  name of file to write decrypted secret key
	 */
	static void decryptKey(String encKeyFile, String privKeyFile, String secKeyFile) {
		// get the aes from the enc

		SecretKeySpec secretkey = null;
		KeyFactory keyfac = null;
		PKCS8EncodedKeySpec tem = null;
		byte[] bytes = null;
		PrivateKey pvt = null;
		byte[] keyb = null;
		try {
			keyb = Files.readAllBytes(Paths.get(encKeyFile));
			secretkey = new SecretKeySpec(keyb, "AES");
		} catch (IOException e3) {
			e3.printStackTrace();
		}

		//making a private rsa
		try {
			bytes = Files.readAllBytes(Paths.get(privKeyFile));
			tem = new PKCS8EncodedKeySpec(bytes);
			keyfac = KeyFactory.getInstance("RSA");
			pvt = keyfac.generatePrivate(tem);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e2) {
			e2.printStackTrace();
		}


		// get cipher ready for decryption
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, pvt);
		} catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e1)  {
			e1.printStackTrace();
		}

		// obtaiinging the output

		byte[] temp3 = null;
		try {
			FileOutputStream out = new FileOutputStream(secKeyFile);
			temp3 = cipher.doFinal(secretkey.getEncoded());
			out.write(temp3);
		} catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Main Program Runner
	 */
	public static void main(String[] args) throws Exception{

		String func;

		if(args.length < 1) {
			func = "";
		} else {
			func = args[0];
		}

		switch(func)
		{
			case "generatekey":
				if(args.length != 2) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr generatekey <key output file>");
					break;
				}
				System.out.println("Generating secret key and writing it to " + args[1]);
				generateKey(args[1]);
				break;
			case "encryptfile":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
					break;
				}
				System.out.println("Encrypting " + args[1] + " with key " + args[2] + " to "  + args[3]);
				encryptFile(args[1], args[2], args[3]);
				break;
			case "decryptfile":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
					break;
				}
				System.out.println("Decrypting " + args[1] + " with key " + args[2] + " to " + args[3]);
				decryptFile(args[1], args[2], args[3]);
				break;
			case "encryptkey":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file>");
					break;
				}
				System.out.println("Encrypting key file " + args[1] + " with public key file " + args[2] + " to " + args[3]);
				encryptKey(args[1], args[2], args[3]);
				break;
			case "decryptkey":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
					break;
				}
				System.out.println("Decrypting key file " + args[1] + " with private key file " + args[2] + " to " + args[3]);
				decryptKey(args[1], args[2], args[3]);
				break;
			default:
				System.out.println("Invalid Arguments.");
				System.out.println("Usage:");
				System.out.println("  Cryptr generatekey <key output file>");
				System.out.println("  Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
				System.out.println("  Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
				System.out.println("  Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file> ");
				System.out.println("  Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
		}

		System.exit(0);

	}

}