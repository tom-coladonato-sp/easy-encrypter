package com.sailpoint;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.Argument;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

public class EasyEncrypter {
	public static void main(String[] args) {
		ArgumentParser parser = ArgumentParsers
				.newFor("EasyEncrypter")
				.build()
					.defaultHelp(true)
					.description("easyEncrypter will help you encrypt something with a X509 public key");
		parser.addArgument("-p", "--plaintext").help("plaintext to encrypt").required(true);
		parser.addArgument("-k", "--key").help("base64Url encoded x509 public key").required(true);
		final Namespace parsedArgs;
		try {
			Security.addProvider(new BouncyCastleProvider());
			parsedArgs = parser.parseArgs(args);
			final String key = parsedArgs.get("key");

			final byte[] plaintext = parsedArgs.getString("plaintext").getBytes(StandardCharsets.UTF_8);

			final byte[] decodedKey = Base64.getUrlDecoder().decode(key.getBytes(StandardCharsets.UTF_8));
			final String cipherText = encrypt(decodedKey, plaintext);

			System.out.println("cipher length: " + cipherText.length());
			System.out.println("ENCRYPTED PAYLOAD FOLLOWS\n======\n\n");
			System.out.println(cipherText);
			System.out.flush();

			System.exit(0);
		} catch (ArgumentParserException e) {
			parser.handleError(e);
			System.exit(1);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | InvalidCipherTextException e) {
			System.err.println("Crypto error\n=====\n" + e.getLocalizedMessage());
			System.exit(1);
		} catch (RuntimeException e) {
			System.err.println("Runtime error\n=====\n" + e.getLocalizedMessage());
			System.exit(1);
		}
	}

	protected static String encrypt(byte[] x509, byte[] plaintext) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidCipherTextException {
		final KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
		final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(x509));

		final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
		final RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(
				false,
				rsaPublicKey.getModulus(),
				rsaPublicKey.getPublicExponent()
		);
		final PKCS1Encoding cipher = new PKCS1Encoding(new RSAEngine());
		cipher.init(true, rsaKeyParameters);
		final byte[] cipherBytes = cipher.processBlock(plaintext, 0, plaintext.length);
		final byte[] encodedCipherBytes = Base64.getUrlEncoder().encode(cipherBytes);
		return new String(encodedCipherBytes, StandardCharsets.UTF_8);
	}
}
