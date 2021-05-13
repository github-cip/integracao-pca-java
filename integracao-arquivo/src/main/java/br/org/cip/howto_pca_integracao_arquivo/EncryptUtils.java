package br.org.cip.howto_pca_integracao_arquivo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;

public class EncryptUtils {
	public static void signEncrypt(String inFile, String outFile, RSAKey senderRsaPrivateKey, X509Certificate senderCertificate,
			X509Certificate recipientCertificate) throws JOSEException, FileNotFoundException, IOException {
		Payload payload = new Payload(FileUtils.readFileToString(new File(inFile), StandardCharsets.UTF_8));
		
		final String senderCertificateSerialHex = StringUtils.leftPad(senderCertificate.getSerialNumber().toString(16), 32, '0');
		final String senderCertificateThumbPrint256 = X509CertUtils.computeSHA256Thumbprint(senderCertificate).toString();
		
		JWSObject jwsObject = new JWSObject(
				new JWSHeader.Builder(JWSAlgorithm.RS256)
					.keyID(senderCertificateSerialHex)
					.x509CertSHA256Thumbprint(new Base64URL(senderCertificateThumbPrint256))
					.build() 
				, payload);
		
		jwsObject.sign(new RSASSASigner(senderRsaPrivateKey));

		final String recipentCertificateSerialHex = StringUtils.leftPad(recipientCertificate.getSerialNumber().toString(16), 32, '0');
		final String recipentCertificateThumbPrint256 = X509CertUtils.computeSHA256Thumbprint(recipientCertificate).toString();

		JWEObject jweObject = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
					.contentType("JWT")
					.compressionAlgorithm(CompressionAlgorithm.DEF)
					.keyID(recipentCertificateSerialHex)
					.x509CertSHA256Thumbprint(new Base64URL(recipentCertificateThumbPrint256))
					.build(), 
				new Payload(jwsObject));

		// Encrypt with the recipient's public key
		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) recipientCertificate.getPublicKey()));

		IOUtils.write(jweObject.serialize().getBytes(), new FileOutputStream(outFile));
	}

	public static void decryptVerifySign(String inFile, String outFile, RSAKey recipientPrivateKey, X509Certificate senderCertificate) throws IOException, ParseException, JOSEException {
		String jweString = FileUtils.readFileToString(new File(inFile), StandardCharsets.UTF_8);
		
		// Parse the JWE string
		JWEObject jweObjectDecript = JWEObject.parse(jweString);

		// Decrypt with private key
		jweObjectDecript.decrypt(new RSADecrypter(recipientPrivateKey));

		// Extract payload
		SignedJWT signedJWTDecript = jweObjectDecript.getPayload().toSignedJWT();

		// Check the signature
		if (signedJWTDecript.verify(new RSASSAVerifier((RSAPublicKey) senderCertificate.getPublicKey()))) {
			org.apache.commons.io.IOUtils.write(signedJWTDecript.getPayload().toBytes(), new FileOutputStream(outFile));
		}
	}
	
	public static RSAKey getRsaKey(String pemFile) throws IOException, JOSEException {
		ClassLoader classLoader = App.class.getClassLoader();
		final String privateKey = com.nimbusds.jose.util.IOUtils.readInputStreamToString(classLoader.getResourceAsStream(pemFile));
		return JWK.parseFromPEMEncodedObjects(privateKey).toRSAKey();
	}
}
