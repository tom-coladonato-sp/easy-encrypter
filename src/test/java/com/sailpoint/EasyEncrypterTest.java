package com.sailpoint;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EasyEncrypterTest {

	@Test
	public void testEncrypter() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidCipherTextException, InvalidKeySpecException {
		Security.addProvider(new BouncyCastleProvider());
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048, new SecureRandom());
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		final byte[] encodedPublicKey = Base64.getUrlEncoder().encode(keyPair.getPublic().getEncoded());
		final String encrypted = EasyEncrypter.encrypt(Base64.getUrlDecoder().decode(encodedPublicKey), "TEST".getBytes(StandardCharsets.UTF_8));

		final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
		final RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(
				true,
				rsaPrivateKey.getModulus(),
				rsaPrivateKey.getPrivateExponent()
		);
		final PKCS1Encoding decipher = new PKCS1Encoding(new RSAEngine());
		decipher.init(false, rsaKeyParameters);

		final byte[] cipherBytes = Base64.getUrlDecoder().decode(encrypted);
		byte[] decryptedBytes = decipher.processBlock(cipherBytes, 0, cipherBytes.length);
		final String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
		System.out.println(decrypted);
		assertEquals("TEST", decrypted);
	}

	@Test
	public void loopTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidCipherTextException, InvalidKeySpecException {
		Security.addProvider(new BouncyCastleProvider());
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048, new SecureRandom());
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		String PUBLIC = new String(Base64.getUrlEncoder().encode(keyPair.getPublic().getEncoded()), StandardCharsets.UTF_8);
		String PRIVATE = new String(Base64.getUrlEncoder().encode(keyPair.getPrivate().getEncoded()), StandardCharsets.UTF_8);

		final String plaintext = "{\"username\":\"devusr_01\",\"password\":\"Pass1234\"}";

		final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getUrlDecoder().decode(PUBLIC.getBytes(StandardCharsets.UTF_8)));

		System.out.println("plaintext: " + plaintext);

		final String cipher = EasyEncrypter.encrypt(x509EncodedKeySpec.getEncoded(), plaintext.getBytes(StandardCharsets.UTF_8));

		System.out.println("cipher: " + cipher);
		System.out.println("cipher length: " + cipher.length());

		final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getUrlDecoder().decode(PRIVATE.getBytes(StandardCharsets.UTF_8)));
		final KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");

		final PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
		final RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(
				true,
				rsaPrivateKey.getModulus(),
				rsaPrivateKey.getPrivateExponent()
		);
		final PKCS1Encoding decipher = new PKCS1Encoding(new RSAEngine());
		decipher.init(false, rsaKeyParameters);

		final byte[] de64 = Base64.getUrlDecoder().decode(cipher);
		byte[] decryptedBytes = decipher.processBlock(de64, 0, de64.length);
		final String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
		System.out.println("decrypted: " + decrypted);
	}
}