/* 
 * � concedida permiss�o a qualquer pessoa que obtenha uma c�pia do c�digo fonte, sendo que o c�digo fonte fornecido 
 * n�o tem qualquer garantia expressa ou impl�cita, em nenhum caso autores deste c�digo, ou titulares dos diretos
 * autorais s�o respons�veis por qualquer reivindica��o, danos, ou quaisquer responsabilidades decorrente de conex�o
 *  ou com o uso deste c�digo fonte em qualquer segmento, neg�cios ou outros softwares.
 * 
 * */

package br.org.cip.howto_pca_integracao_arquivo;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.text.ParseException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FileUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertUtils;

public class App {

	public static void main(String args[]) throws KeyLengthException, JOSEException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ParseException,
			InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, IOException, InterruptedException {
		RSAKey senderPrivateKey = EncryptUtils.getRsaKey("87654321_priv_decrypted.pem");
		X509Certificate senderCertificate = X509CertUtils.parse(IOUtils.readInputStreamToString(App.class.getClassLoader().getResourceAsStream("87654321.cer")));
		X509Certificate recipientCertificate = X509CertUtils.parse(IOUtils.readInputStreamToString(App.class.getClassLoader().getResourceAsStream("cip.cer")));
		
		System.out.println("1. Construindo uma requisição, em formato definido no manual de leiautes");
		String payload = "{}";
		org.apache.commons.io.IOUtils.write(payload.getBytes(), new FileOutputStream("req-payload.json"));
		
		System.out.println("\n\n----------");
		System.out.println("2. Assinando e encriptando o arquivo no modo compacto de serialização do JWE");
		EncryptUtils.signEncrypt("req-payload.json", "req.dat", senderPrivateKey, senderCertificate, recipientCertificate);
		
		System.out.println("\n\n----------");
		System.out.println("3. Enviando para a CIP esse arquivo de requisição, já em modo compacto de serialização do JWE ");
		Utils.sendToCip("req.dat");
		
		System.out.println("\n\n----------");
		System.out.println("4. Após o processamento desse arquivo de requisição, a CIP enviará de volta um arquivo de resposta, também no modo compacto de serialização do JWE, neste exemplo, o arquivo \"resp.dat\"");
		
		System.out.println("\n\n----------");
		System.out.println("5. O arquivo de resposta");
		System.out.println("Verificando assinatura do arquivo de resposta e iniciando decriptação");
		EncryptUtils.decryptVerifySign("resp.dat", "resp-payload.json", senderPrivateKey, recipientCertificate);
		
		
		System.out.println("\n\n----------");
		System.out.println("6. A resposta posicional está agora disponível, para ser processada pelo sistema do Participante, de acordo com o formato de resposta definido no manual de leiautes.");
		System.out.println(FileUtils.readFileToString(new File("resp-payload.json"), StandardCharsets.UTF_8));
	}
}
