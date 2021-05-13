package br.org.cip.howto_pca_integracao_arquivo;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertUtils;

public class Utils {

	public static void sendToCip(String string) throws IOException, JOSEException, InterruptedException {
		System.out.println("Arquivo enviado à CIP. Aguardando arquivo de resposta...");
		Thread.sleep(2000);
		
		RSAKey senderPrivateKey = EncryptUtils.getRsaKey("cip_priv_decrypted.pem");
		X509Certificate senderCertificate = X509CertUtils.parse(IOUtils.readInputStreamToString(App.class.getClassLoader().getResourceAsStream("cip.cer")));
		X509Certificate recipientCertificate = X509CertUtils.parse(IOUtils.readInputStreamToString(App.class.getClassLoader().getResourceAsStream("87654321.cer")));
		
		String payload = "{resultado: \"PROCESSAMENTO-OK\"}";
		org.apache.commons.io.IOUtils.write(payload.getBytes(), new FileOutputStream("resp-payload.json"));
		
		EncryptUtils.signEncrypt("resp-payload.json", "resp.dat", senderPrivateKey, senderCertificate, recipientCertificate);
		
	}

}
