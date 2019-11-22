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

public class Cryptr {

	private static final SecureRandom srandom = new SecureRandom();

	/**
	 * Generates an 128-bit AES secret key and writes it to a file
	 *
	 * @param secKeyFile name of file to store secret key
	 */
	static void generateKey(String secKeyFile) throws Exception {
		// Generate AES Key, 128 bits
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		SecretKey skey = kgen.generateKey();

		// Output key to file
		FileOutputStream outStream = null;
		try {
			outStream = new FileOutputStream(secKeyFile);
			byte[] keyBytes = skey.getEncoded();
			outStream.write(keyBytes);
			outStream.close();
		} catch (Exception ex) {
			throw new Exception("Error in outputting key to file. " + ex.getMessage(), ex);
		}
	}

	/**
	 * Extracts secret key from a file, generates an initialization vector, uses
	 * them to encrypt the original file, and writes an encrypted file containing
	 * the initialization vector followed by the encrypted file data
	 *
	 * @param originalFile  name of file to encrypt
	 * @param secKeyFile    name of file storing secret key
	 * @param encryptedFile name of file to write iv and encrypted file data
	 */
	static void encryptFile(String originalFile, String secKeyFile, String encryptedFile) {
		// === Import secret Key from file
		byte[] keyBytes = null;
		SecretKeySpec sKey = null;
		try {
			keyBytes = Files.readAllBytes(Paths.get(secKeyFile));
			sKey = new SecretKeySpec(keyBytes, "AES");
		} catch (IOException e) {
			e.printStackTrace();
		} // IOException

		// === Initialization Vector
		byte[] iv = new byte[128 / 8];
		srandom.nextBytes(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		// === Cipher Creation
		String cipherType = "AES/CBC/PKCS5Padding";
		Cipher ciph = null;
		try {
			ciph = Cipher.getInstance(cipherType); // e1 error
			ciph.init(Cipher.ENCRYPT_MODE, sKey, ivspec); // e2 error
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			e1.printStackTrace();
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e2) {
			e2.printStackTrace();
		}

		// === Open original file => Encrypt => Output
		FileInputStream inOriStream = null;
		FileOutputStream outEncryptStream = null;
		try {
			// open files
			inOriStream = new FileInputStream(originalFile); 
			outEncryptStream = new FileOutputStream(encryptedFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		try {
			outEncryptStream.write(iv);
			byte[] ibuf = new byte[1024];
			int len;
			while ((len = inOriStream.read(ibuf)) != -1) {
				byte[] obuf = ciph.update(ibuf, 0, len);
				if (obuf != null)
					outEncryptStream.write(obuf);
			}
			byte[] obuf = ciph.doFinal();
			if (obuf != null)
				outEncryptStream.write(obuf);
		} catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Extracts the secret key from a file, extracts the initialization vector from
	 * the beginning of the encrypted file, uses both secret key and initialization
	 * vector to decrypt the encrypted file data, and writes it to an output file
	 *
	 * @param encryptedFile name of file storing iv and encrypted data
	 * @param secKeyFile    name of file storing secret key
	 * @param outputFile    name of file to write decrypted data to
	 */
	static void decryptFile(String encryptedFile, String secKeyFile, String outputFile) {
		// Read Initialization Vector + Extract IV
		FileInputStream inIVStream = null;
		byte[] iv = new byte[128 / 8];
		try {
			inIVStream = new FileInputStream(encryptedFile);
			inIVStream.read(iv);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// IVSpec + loading secret key
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		byte[] keyBytes;
		SecretKeySpec sKey = null;
		try {
			keyBytes = Files.readAllBytes(Paths.get(secKeyFile));
			sKey = new SecretKeySpec(keyBytes, "AES");
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Initialize Cipher to Decryption Mode
		String cipherType = "AES/CBC/PKCS5Padding";
		Cipher ciph = null;
		try {
			ciph = Cipher.getInstance(cipherType);
			ciph.init(Cipher.DECRYPT_MODE, sKey, ivspec);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			e1.printStackTrace();
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e2) {
			e2.printStackTrace();
		}

		//  Decrypt file
		FileInputStream input = null;
		FileOutputStream outDecryptStream = null;
		try {
			input = inIVStream;
			outDecryptStream = new FileOutputStream(outputFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		byte[] ibuf = new byte[1024];
		int len;
		try {
			while ((len = input.read(ibuf)) != -1) {
				byte[] obuf = ciph.update(ibuf, 0, len);
				if (obuf != null)
					outDecryptStream.write(obuf);
			}
			byte[] obuf = ciph.doFinal();
			if (obuf != null)
				outDecryptStream.write(obuf);
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

		// Load RSA Key
		PublicKey publicKey = null;
		try {
			byte[] RSAbytes = Files.readAllBytes(Paths.get(pubKeyFile));
			X509EncodedKeySpec ks = new X509EncodedKeySpec(RSAbytes);
			KeyFactory keyfac = KeyFactory.getInstance("RSA");
			publicKey = keyfac.generatePublic(ks);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}

		// load AES secret key
		SecretKeySpec skey = null;
		try {
			byte[] AESkeybytes = Files.readAllBytes(Paths.get(secKeyFile));
			skey = new SecretKeySpec(AESkeybytes, "AES");
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Initialize Cipher for encryption
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}

		// Output
		try {
			FileOutputStream out = new FileOutputStream(encKeyFile);
			byte[] b = cipher.doFinal(skey.getEncoded());
			out.write(b);
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
		// load AES from encKey
		SecretKeySpec skey = null;
		try {
			byte[] keyb = Files.readAllBytes(Paths.get(encKeyFile));
			skey = new SecretKeySpec(keyb, "AES");
		} catch (IOException e3) {
			e3.printStackTrace();
		}

		// Private RSA 
		PrivateKey pvt = null;
		try {
			byte[] bytes = Files.readAllBytes(Paths.get(privKeyFile));
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			pvt = kf.generatePrivate(ks);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e2) {
			e2.printStackTrace();
		}

		// Initialize Cipher for decryption
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, pvt);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e1) {
			e1.printStackTrace();
		}

		// Output
		try {
			FileOutputStream out = new FileOutputStream(secKeyFile);
			byte[] b = cipher.doFinal(skey.getEncoded());
			out.write(b);
		} catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Main Program Runner
	 */
	public static void main(String[] args) throws Exception {

		String func;

		if (args.length < 1) {
			func = "";
		} else {
			func = args[0];
		}

		switch (func) {
		case "generatekey":
			if (args.length != 2) {
				System.out.println("Invalid Arguments.");
				System.out.println("Usage: Cryptr generatekey <key output file>");
				break;
			}
			System.out.println("Generating secret key and writing it to " + args[1]);
			generateKey(args[1]);
			break;
		case "encryptfile":
			if (args.length != 4) {
				System.out.println("Invalid Arguments.");
				System.out.println(
						"Usage: Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
				break;
			}
			System.out.println("Encrypting " + args[1] + " with key " + args[2] + " to " + args[3]);
			encryptFile(args[1], args[2], args[3]);
			break;
		case "decryptfile":
			if (args.length != 4) {
				System.out.println("Invalid Arguments.");
				System.out.println(
						"Usage: Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
				break;
			}
			System.out.println("Decrypting " + args[1] + " with key " + args[2] + " to " + args[3]);
			decryptFile(args[1], args[2], args[3]);
			break;
		case "encryptkey":
			if (args.length != 4) {
				System.out.println("Invalid Arguments.");
				System.out.println(
						"Usage: Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file>");
				break;
			}
			System.out
					.println("Encrypting key file " + args[1] + " with public key file " + args[2] + " to " + args[3]);
			encryptKey(args[1], args[2], args[3]);
			break;
		case "decryptkey":
			if (args.length != 4) {
				System.out.println("Invalid Arguments.");
				System.out.println(
						"Usage: Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
				break;
			}
			System.out
					.println("Decrypting key file " + args[1] + " with private key file " + args[2] + " to " + args[3]);
			decryptKey(args[1], args[2], args[3]);
			break;
		default:
			System.out.println("Invalid Arguments.");
			System.out.println("Usage:");
			System.out.println("  Cryptr generatekey <key output file>");
			System.out.println("  Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
			System.out.println("  Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
			System.out
					.println("  Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file> ");
			System.out
					.println("  Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
		}

		System.exit(0);

	}

}
