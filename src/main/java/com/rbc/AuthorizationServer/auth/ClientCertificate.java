package com.rbc.AuthorizationServer.auth;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;

import com.rbc.AuthorizationServer.config.OAuth2Config;
import com.rbc.AuthorizationServer.exception.CustomException;
import com.rbc.AuthorizationServer.utils.Constants;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * This class is used to generate client assertion using private key and public
 * key and then used to generate the access token
 * 
 * @author anushkak
 *
 */
@Service
public class ClientCertificate {

	Logger log = LogManager.getLogger(ClientCertificate.class);
	OAuth2Config oauthconfig;

	/**
	 * This method is used to get the private key from config file and decode base64
	 * and convert it inot PrivateKey
	 * 
	 * @param oauthconfig configuration value
	 * @return private key to be used to sign the certificate
	 * @throws IOException              i/o erro
	 * @throws NoSuchAlgorithmException when no algorithm was found
	 * @throws InvalidKeySpecException  when there is invalid key found
	 */
	public PrivateKey getPrivateKey(OAuth2Config oauthconfig)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		// getting private key from config file
		String rsaPrivateKey = oauthconfig.getPrivateKey();
		// decoding to base64
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(rsaPrivateKey));
		KeyFactory kf = KeyFactory.getInstance(Constants.RSA);
		PrivateKey privKey = kf.generatePrivate(keySpec);
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
				+ ", with private key value: " + privKey);

		return privKey;
	}

	/**
	 * This method is used generate certificate using public key
	 * 
	 * @param rsaPublicKey passed from config file
	 * @return thumbprint extracted from generated certificate
	 * @throws IOException              i/o error
	 * @throws CertificateException     while genrating certificate
	 * @throws NoSuchAlgorithmException when no algorithm is found
	 */
	public String getCertObject(String rsaPublicKey)
			throws IOException, CertificateException, NoSuchAlgorithmException {
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		InputStream is = new ByteArrayInputStream(rsaPublicKey.getBytes(Charset.forName(Constants.UTF8)));
		CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.X509);
		X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(is);

		String thumbPrint = getThumbprint(cert);
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
				+ ", with thumbprint value: " + thumbPrint);

		return thumbPrint;
	}

	/**
	 * This method is used to extract thumbprint from the certificate generated
	 * 
	 * @param cert certificate from which thumbprint to be extracted
	 * @return thumbprint value
	 * @throws NoSuchAlgorithmException     when no algorithm is found
	 * @throws CertificateEncodingException when certificate fails to encode
	 */
	public String getThumbprint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {

		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		MessageDigest md = MessageDigest.getInstance(Constants.SHA1);
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		String digestHex = DatatypeConverter.printHexBinary(digest);
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		return digestHex.toLowerCase();

	}

	/**
	 * This method is used to convert thumbprint value from Hex to base64
	 * 
	 * @param thumbprint value to be converted to hexadecimal
	 * @return bas64 thumbprint value
	 */
	public String convertHexToBase64(String thumbprint) {
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		BigInteger bigint = new BigInteger(thumbprint, 16);
		StringBuilder sb = new StringBuilder();
		byte[] ba = Base64.encodeInteger(bigint);

		for (byte b : ba) {
			sb.append((char) b);
		}
		String encodedThumbprint = sb.toString();
		String resultThumbprint = encodedThumbprint.substring(0, encodedThumbprint.indexOf("="));
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
				+ ", with base64 value of thumbprint: " + resultThumbprint);

		return resultThumbprint;
	}

	/**
	 * This method is used to generate cryptographically secure pseudo random-number
	 * for the jwt claims using default algorithm SHA1PRNG algorithm
	 * 
	 * @return JwtId created using cryptographically secure pseudo random-number
	 */
	public String generateId() {
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		SecureRandom sr = new SecureRandom();
		byte[] code = new byte[32];
		sr.nextBytes(code);
		String JwtId = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(code);
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		return JwtId;
	}

	/**
	 * This method is used to generate the Jwt token with key by setting header and
	 * payload and sign the certificate with private key
	 * 
	 * @param oauthconfig configuration values
	 * @return jwt token for client assertion
	 */
	public String generateJwtTokenWithKey(OAuth2Config oauthconfig) {

		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		// getting values from application.properties file
		String configThumbprint = oauthconfig.getThumbprint();
		String Issuer = oauthconfig.getIssuer();
		String clientId = oauthconfig.getClientId();
		String rsaPublicKey = oauthconfig.getPublicKey();
		String base64Thumbprint = "";
		String JwtId = generateId();
		String jwtToken = "";

		try {
			// getting signing key to sign the certificate
			PrivateKey signingKey = getPrivateKey(oauthconfig);

			// validating thumbprint value extracted from certificate generated and compare
			// with thumbprint passed from config file
			String thumbprint = getCertObject(rsaPublicKey);
			if (!configThumbprint.equals(thumbprint)) {
				throw new AuthenticationServiceException("Public Key token has Invalid Thumbprint");
			} else {
				base64Thumbprint = convertHexToBase64(thumbprint);
			}

			// generating client assertion
			Instant now = Instant.now();
			// Header<Header<T>>
			jwtToken = Jwts.builder().setHeaderParam(Constants.ALGORITHM, Constants.RS256)
					.setHeaderParam(Constants.TYPE, Constants.JWT).setAudience(Issuer)
					.setHeaderParam(Constants.X5T, base64Thumbprint).setSubject(clientId).setId(JwtId)
					.setNotBefore(Date.from(now)).setIssuer(clientId).setIssuedAt(Date.from(now))
					.setExpiration(Date.from(now.plus(5, ChronoUnit.MINUTES)))
					.signWith(SignatureAlgorithm.RS256, signingKey).compact();

			// logging activity
			log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", with jwt token value.. ");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | CertificateException e) {
			log.error("Exception occured in client credential: "
					+ Thread.currentThread().getStackTrace()[1].getMethodName() + " Failed to generate the token JTI");
			throw new CustomException(Constants.BAD_REQUEST, "Failed to generate JTI");
		}
		return jwtToken;

	}

}
