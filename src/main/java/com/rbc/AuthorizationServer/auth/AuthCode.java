package com.rbc.AuthorizationServer.auth;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.rbc.AuthorizationServer.config.OAuth2Config;
import com.rbc.AuthorizationServer.config.SetProxyAndSSL;
import com.rbc.AuthorizationServer.exception.CustomException;
import com.rbc.AuthorizationServer.exception.UnauthorizedException;
import com.rbc.AuthorizationServer.utils.Constants;
import com.rbc.AuthorizationServer.utils.TokenGlobals;

@Service
/**
 * .SYNOPSIS This class is created to genrate code verifier, code challenge,
 * nonce, codeUrl and get the token value from the well known token url
 * 
 * .DESCRIPTION This class has method in which token url has passed for
 * authcode+pkce pattern, grant type and resource to get the token value
 * 
 * .Method getCodeVerifier(),
 * getCodeChallenge(),createNonce(),generateCodeUrl(),getAccessTokenBySecret(),getAccessTokenByCertificate(),
 * getAccessTokenByCertificate(),
 * getRefreshTokenByCertificate(),getRefreshTokenBySecret()
 * 
 * @author anushkak
 *
 */
public class AuthCode {

	ClientCertificate clientCertificate = new ClientCertificate();
	public OAuth2Config oauthconfig = new OAuth2Config();
	SetProxyAndSSL setProxy = new SetProxyAndSSL();
	static Logger log = LogManager.getLogger(AuthCode.class);
	int retryCount = 0;
	int delayTime = 0;

	/**
	 * .SYNOPSIS This method is used to generate code verifier to generate code url
	 * .DESCRIPTION This method uses random string everytime to generate code
	 * verifier to get the token value
	 * 
	 * @return codeVerifier generated with secure random
	 */
	public static String getCodeVerifier() {
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		SecureRandom sr = new SecureRandom();
		byte[] code = new byte[32];
		sr.nextBytes(code);
		String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(code);
		// initializing code verifier to global variable
		TokenGlobals.globalCodeVerifier = codeVerifier;

		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
				+ "with code verifier ");
		return TokenGlobals.globalCodeVerifier;
	}

	/**
	 * .SYNOPSIS This method generates code challenge using code verifier generated
	 * at runtime to generate code url .DESCRIPTION This method generates code
	 * challenge using code verifier generated at runtime to generate code url
	 * 
	 * @return code challenge generated using code verifier
	 * @throws UnsupportedEncodingException when encoding fails
	 * @throws NoSuchAlgorithmException     when no algorithm is found
	 */
	public static String getCodeChallenge() throws UnsupportedEncodingException, NoSuchAlgorithmException {
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		String codeVerifier = getCodeVerifier();
		byte[] bytes = codeVerifier.getBytes(Constants.USASCII);
		MessageDigest md = MessageDigest.getInstance(Constants.SHA256);
		md.update(bytes, 0, bytes.length);
		byte[] digest = md.digest();
		String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		// initializing code challenge to global variable
		TokenGlobals.globalCodeChallenge = codeChallenge;
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
				+ "with code Challenge ");
		return TokenGlobals.globalCodeChallenge;
	}

	/**
	 * .SYNOPSIS This method is used to generate nonce to generate code url
	 * .DESCRIPTION This method uses random string to generate nonce
	 * 
	 * @return nonce secure random number generated
	 * @throws NoSuchAlgorithmException when no algorithm found
	 */
	// generate nonce to generate code url
	public String createNonce() throws NoSuchAlgorithmException {
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		String nonce = "";
		SecureRandom prng = SecureRandom.getInstance(Constants.SHA1PRNG);
		String randomNum = String.valueOf(prng.nextInt());
		MessageDigest sha = MessageDigest.getInstance(Constants.SHA1);
		byte[] result = sha.digest(randomNum.getBytes());
		nonce = hexEncode(result);
		TokenGlobals.globalNonce = nonce;

		// logging activity
		log.debug(
				"Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName() + "with nonce value ");
		return TokenGlobals.globalNonce;
	}

	// This method encodes the hex value of byte result of nonce
	public static String hexEncode(byte[] aInput) {
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		StringBuilder result = new StringBuilder();

		char[] digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
		for (int idx = 0; idx < aInput.length; ++idx) {
			byte b = aInput[idx];
			result.append(digits[(b & 0xf0) >> 4]);
			result.append(digits[b & 0x0f]);
		}
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		return result.toString();
	}

	/**
	 * .SYNOPSIS This method is used to generate nonce to generate code url
	 * .DESCRIPTION This method uses random string to generate nonce
	 * 
	 * @return state secure random number generated
	 * @throws NoSuchAlgorithmException when no algorithm is found
	 */
	// generate nonce to generate code url
	public String generateState(OAuth2Config oauthconfig) {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		String fingerprint = oauthconfig.getFingerprint();
		String sessionId = oauthconfig.getSessionId();
		String state = Integer.toString(fingerprint.concat(sessionId).hashCode());
		TokenGlobals.State = state;
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		return TokenGlobals.State;

	}

	   /**
     * .SYNOPSIS This method is used to generate the code url for auth code+pkce
     * pattern .DESCRIPTION This method uses configuration values to generate the
     * code url
     * 
      * @param oauthconfig configuration from application.properties file
     * @return generated code URL
     * @throws UnsupportedEncodingException when encoding fails
     * @throws NoSuchAlgorithmException     when no algorithm is found
     */
	public String generateCodeUrl(OAuth2Config oauthconfig)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		String codeChallengeUri = oauthconfig.getCodeChallengeUri();
		String clientId = oauthconfig.getClientId();
		String codeResponseType = oauthconfig.getCodeResponseType();
		String redirectUri = oauthconfig.getRedirectUri();
		String scope = oauthconfig.getScope();
		String codeChallenge = getCodeChallenge();
		String nonce = createNonce();
		String state = generateState(oauthconfig);

		String string = "";
		String codeUri = string.concat(codeChallengeUri + "?" + Constants.CLIENT_ID + "=" + clientId + "&"
				+ Constants.RESPONSE_TYPE + "=" + codeResponseType + "&" + Constants.REDIRECT_URI + "=" + redirectUri
				+ "&" + Constants.SCOPE + "=" + scope + "&" + Constants.CODE_CHALLENGE + "=" + codeChallenge + "&"
				+ Constants.CODE_CHALLENGE_METHOD + "=" + Constants.CODE_CHALLENGE_METHOD_ALG + "&" + Constants.NONCE
				+ "=" + nonce + "&" + Constants.STATE + "=" + state);
		// logging activity
		log.info("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		return codeUri;

	}

	/**
	 * .SYNOPSIS This method is used to get the token value using client secret for
	 * auth code+pkce pattern
	 * 
	 * .DESCRIPTION This method uses unirest Http client library to fetch the token
	 * value by passing the client secret and grant type
	 * 
	 * @param oauthconfig configuration values from application.properties file
	 * @return the token value generated by passing client secret
	 */

	public String getAccessTokenBySecret(OAuth2Config oauthconfig) {
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		// getting values from configuration file
		String clientId = oauthconfig.getClientId();
		String clientSecret = oauthconfig.getClientSecret();
		String grantType = oauthconfig.getGrantType();
		String redirectUri = oauthconfig.getRedirectUri();
		String tokenUrl = oauthconfig.getTokenUrl();
		String codeVerifier = TokenGlobals.globalCodeVerifier;
		String code = oauthconfig.getCode();
		String scope = oauthconfig.getScope();
		int retryTimeCount = Integer.parseInt(oauthconfig.getRetryCount().trim());
		delayTime = Integer.parseInt(oauthconfig.getRetryDelayTime().trim());
		String retryExceptions = oauthconfig.getRetryExceptions();
		String token = "";
		if (clientId == null || "".equals(clientId)) {
			throw new UnauthorizedException(Constants.UNAUTHORIZED, "clientId required cannot be null");
		}
		if (clientSecret == null || "".equals(clientSecret)) {
			throw new UnauthorizedException(Constants.UNAUTHORIZED, "clientSecret required cannot be null");
		}

		if (grantType == null || "".equals(grantType)) {
			throw new UnauthorizedException(Constants.UNAUTHORIZED, "grantType required cannot be null");
		}
		if (redirectUri == null || "".equals(redirectUri)) {
			throw new UnauthorizedException(Constants.UNAUTHORIZED, "RedirectUri required cannot be null");
		}
		if (tokenUrl == null || "".equals(tokenUrl)) {
			throw new UnauthorizedException(Constants.UNAUTHORIZED, "tokenUrl required cannot be null");
		}
		if (scope == null || "".equals(scope)) {
			throw new UnauthorizedException(Constants.UNAUTHORIZED, "scope required cannot be null");
		}
		if (oauthconfig.getRetryCount() == null || "".equals(oauthconfig.getRetryCount())) {
			throw new UnauthorizedException(Constants.UNAUTHORIZED, "retry count required cannot be null");
		}
		if (retryExceptions == null || "".equals(retryExceptions)) {
			throw new UnauthorizedException(Constants.UNAUTHORIZED, "retryException required cannot be null");
		}

		String credentials = String.format(
				"grant_type= %s &client_id= %s& client_secret= %s &code_verifier= %s"
						+ "&code= %s &redirect_uri= %s  &scope = %s",
				grantType, clientId, clientSecret, codeVerifier, code, redirectUri, scope);

		try {
			// setting proxy before unirest api call
//			CloseableHttpClient httpclient = setProxy.getHttpClient();
//			Unirest.setHttpClient(httpclient);
			HttpResponse<JsonNode> response = Unirest.post(tokenUrl)
					.header("content-type", "application/x-www-form-urlencoded").body(credentials).asJson();
			// getting json response into string token value
			token = response.getBody().toString();

			if (new JSONObject(token).has(Constants.ERROR)) {
				String error = (String) new JSONObject(token).get(Constants.ERROR);
				if (null != error || !error.equals("") && retryExceptions.contains(error)) {
					JSONObject jsn = new JSONObject(token);

					delayTime = jsn.has(Constants.RETRYAFTER) ? (int) new JSONObject(token).get(Constants.RETRYAFTER)
							: delayTime;
					if (retryCount < retryTimeCount) {
						retryCount++;
						delayTime = (int) (Math.pow(2d, Double.valueOf(retryCount)) * delayTime);
						log.debug("Retry count : " + retryCount + ", Delay Time : " + delayTime + ", Error : " + error);
						Thread.sleep(delayTime);
						return getAccessTokenBySecret(oauthconfig);
					} else {
						log.error("Exception occured in client credential: "
								+ Thread.currentThread().getStackTrace()[1].getMethodName()
								+ " Failed to generate the token");
						throw new CustomException(Constants.BAD_REQUEST, "Failed to generate token");
					}
				}
			}
			// logging activity
			log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ "and returning token value");

		} catch (UnirestException | InterruptedException e) {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ " Failed to generate the token");
			throw new CustomException(Constants.BAD_REQUEST, "Failed to generate the token");

		}
		return token;
	}

     /**
     * .SYNOPSIS This method is used to get the token value using client assertion
     * for auth code+pkce pattern
     * 
      * .DESCRIPTION This method uses unirest Http client library to fetch the token
     * value by passing the client credentials and grant type
     * 
      * @param oauthconfig configuration values from application.properties file
     * @return the token value generated by passing client assertion
     */
		public String getAccessTokenByCertificate(OAuth2Config oauthconfig) {

			// logging activity
			log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

			// getting values from configuration file
			String clientId = oauthconfig.getClientId();
			String grantType = oauthconfig.getGrantType();
			String tokenUrl = oauthconfig.getTokenUrl();
			String clientAssertionType = oauthconfig.getClientAssertionType();
			String redirectUri = oauthconfig.getRedirectUri();
			String codeVerifier = TokenGlobals.globalCodeVerifier;
			String code = oauthconfig.getCode();
			String scope = oauthconfig.getScope();
			String clientAssertion = clientCertificate.generateJwtTokenWithKey(oauthconfig);
			int retryTimeCount = Integer.parseInt(oauthconfig.getRetryCount().trim());
			delayTime = Integer.parseInt(oauthconfig.getRetryDelayTime().trim());
			String retryExceptions = oauthconfig.getRetryExceptions();
			String token = "";

			if (clientId == null || "".equals(clientId)) {
				throw new UnauthorizedException(Constants.UNAUTHORIZED, "clientId required cannot be null");
			}
			if (clientAssertion == null || "".equals(clientAssertion)) {
				throw new UnauthorizedException(Constants.UNAUTHORIZED, "clientAssertion required cannot be null");
			}
			if (grantType == null || "".equals(grantType)) {
				throw new UnauthorizedException(Constants.UNAUTHORIZED, "grantType required cannot be null");
			}
			if (tokenUrl == null || "".equals(tokenUrl)) {
				throw new UnauthorizedException(Constants.UNAUTHORIZED, "tokenUrl required cannot be null");
			}
			if (scope == null || "".equals(scope)) {
				throw new UnauthorizedException(Constants.UNAUTHORIZED, "scope required cannot be null");
			}
			if (oauthconfig.getRetryCount() == null || "".equals(oauthconfig.getRetryCount())) {
				throw new UnauthorizedException(Constants.UNAUTHORIZED, "retry count required cannot be null");
			}
			if (retryExceptions == null || "".equals(retryExceptions)) {
				throw new UnauthorizedException(Constants.UNAUTHORIZED, "retryException required cannot be null");
			}

			String credentials = String.format(
					"grant_type= %s &client_id= %s& client_assertion=%s &code_verifier= %s"
							+ "&code= %s &redirect_uri= %s &scope = %s &client_assertion_type=%s",
					grantType, clientId, clientAssertion, codeVerifier, code, redirectUri, scope, clientAssertionType);

			try {
				// setting proxy before unirest api call
//				CloseableHttpClient httpclient = setProxy.getHttpClient();
//				Unirest.setHttpClient(httpclient);

				// simple unirest http post request to get the token value
				HttpResponse<JsonNode> response = Unirest.post(tokenUrl)
						.header("content-type", "application/x-www-form-urlencoded").body(credentials).asJson();

				// getting json response into string token value
				token = response.getBody().toString();

				if (new JSONObject(token).has(Constants.ERROR)) {
					String error = (String) new JSONObject(token).get(Constants.ERROR);
					if (null != error || !error.equals("") && retryExceptions.contains(error)) {
						JSONObject jsn = new JSONObject(token);

						delayTime = jsn.has(Constants.RETRYAFTER)
								? (int) new JSONObject(token).get(Constants.RETRYAFTER)
								: delayTime;
						if (retryCount < retryTimeCount) {
							retryCount++;
							delayTime = (int) (Math.pow(2d, Double.valueOf(retryCount)) * delayTime);
							log.debug("Retry count : " + retryCount + ", Delay Time : " + delayTime + ", Error : "
									+ error);
							Thread.sleep(delayTime);
							return getAccessTokenByCertificate(oauthconfig);
						} else {
							log.error("Exception occured in client credential: "
									+ Thread.currentThread().getStackTrace()[1].getMethodName()
									+ " Failed to generate the token");
							throw new CustomException(Constants.BAD_REQUEST, "Failed to generate token");
						}
					}
				}
				// logging activity
				log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
						+ " and returning token value");

			} catch (UnirestException | InterruptedException e) {
				log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
						+ " Failed to generate the tokenFailed to generate the token");
				throw new CustomException(Constants.BAD_REQUEST, "Failed to generate the token");
			}
			return token;
		}

     /**
     * * .SYNOPSIS This method is used to get the token value using client secret
     * for auth code+pkce pattern if the token gets expire
     * 
      * .DESCRIPTION This method uses unirest Http client library to fetch the token
     * value by passing the client secret and refresh token extracted from token
     * metadata, if token gets expire
     * 
      * @param oauthconfig configuration values from application.properties file
     * @return the token value generated by passing client secret
     */

		public String getRefreshTokenBySecret(OAuth2Config oauthconfig) {
			// logging activity
			log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

			// getting values from configuration file
			String clientId = oauthconfig.getClientId();
			String clientSecret = oauthconfig.getClientSecret();
			String grantType = Constants.REFRESHTOKEN;
			String refreshToken = TokenGlobals.refreshToken;
			String scope = oauthconfig.getScope();
			String tokenUrl = oauthconfig.getTokenUrl();
			int retryTimeCount = Integer.parseInt(oauthconfig.getRetryCount().trim());
			delayTime = Integer.parseInt(oauthconfig.getRetryDelayTime().trim());
			String retryExceptions = oauthconfig.getRetryExceptions();
			String token = "";

			String credentials = String.format(
					"grant_type= %s &client_id=%s &client_secret= %s" + "&refresh_token = %s &scope = %s", grantType,
					clientId, clientSecret, refreshToken, scope);
			try {
				// setting proxy before unirest api call
//                                     CloseableHttpClient httpclient = setProxy.getHttpClient();
//                                     Unirest.setHttpClient(httpclient);
				HttpResponse<JsonNode> response = Unirest.post(tokenUrl)
						.header("content-type", "application/x-www-form-urlencoded").body(credentials).asJson();
				token = response.getBody().toString();

				if (new JSONObject(token).has(Constants.ERROR)) {
					String error = (String) new JSONObject(token).get(Constants.ERROR);
					if (null != error || !error.equals("") && retryExceptions.contains(error)) {
						JSONObject jsn = new JSONObject(token);

						delayTime = jsn.has(Constants.RETRYAFTER)
								? (int) new JSONObject(token).get(Constants.RETRYAFTER)
								: delayTime;
						if (retryCount < retryTimeCount) {
							retryCount++;
							delayTime = (int) (Math.pow(2d, Double.valueOf(retryCount)) * delayTime);
							log.debug("Retry count : " + retryCount + ", Delay Time : " + delayTime + ", Error : "
									+ error);
							Thread.sleep(delayTime);
							return getRefreshTokenBySecret(oauthconfig);
						} else {
							log.error("Exception occured in client credential: "
									+ Thread.currentThread().getStackTrace()[1].getMethodName()
									+ " Failed to generate the token");
							throw new CustomException(Constants.BAD_REQUEST, "Failed to generate token");
						}
					}
				}
				// logging activity
				log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
						+ "and returning token value");

			} catch (UnirestException | InterruptedException e) {
				log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
						+ " Failed to generate the token");
				throw new CustomException(Constants.BAD_REQUEST, "Failed to generate the token");

			}

			return token;

		}

     /**
     * * .SYNOPSIS This method is used to get the token value using client assertion
     * for auth code+pkce pattern if the token gets expire
     * 
      * .DESCRIPTION This method uses unirest Http client library to fetch the token
     * value by passing the client assertion and refresh token extracted from token
     * metadata, if token gets expire
     * 
      * @param oauthconfig configuration values from application.properties file
     * @return the token value generated by passing client assertion
     */

		public String getRefreshTokenByCertificate(OAuth2Config oauthconfig) {
			// logging activity
			log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

			// getting values from configuration file
			String clientId = oauthconfig.getClientId();
			String clientAssertion = clientCertificate.generateJwtTokenWithKey(oauthconfig);
			String clientAssertionType = oauthconfig.getClientAssertionType();
			String grantType = Constants.REFRESHTOKEN;
			String refreshToken = TokenGlobals.refreshToken;
			String scope = oauthconfig.getScope();
			String tokenUrl = oauthconfig.getTokenUrl();
			int retryTimeCount = Integer.parseInt(oauthconfig.getRetryCount().trim());
			delayTime = Integer.parseInt(oauthconfig.getRetryDelayTime().trim());
			String retryExceptions = oauthconfig.getRetryExceptions();
			String token = "";

			String credentials = String.format(
					"grant_type= %s &client_id= %s& client_assertion=%s"
							+ "&refresh_token = %s &scope=%s &client_assertion_type=%s",
					grantType, clientId, clientAssertion, refreshToken, scope, clientAssertionType);
			try {
				// setting proxy before unirest api call
//				CloseableHttpClient httpclient = setProxy.getHttpClient();
//				Unirest.setHttpClient(httpclient);
				HttpResponse<JsonNode> response = Unirest.post(tokenUrl)
						.header("content-type", "application/x-www-form-urlencoded").body(credentials).asJson();
				token = response.getBody().toString();

				if (new JSONObject(token).has(Constants.ERROR)) {
					String error = (String) new JSONObject(token).get(Constants.ERROR);
					if (null != error || !error.equals("") && retryExceptions.contains(error)) {
						JSONObject jsn = new JSONObject(token);

						delayTime = jsn.has(Constants.RETRYAFTER)
								? (int) new JSONObject(token).get(Constants.RETRYAFTER)
								: delayTime;
						if (retryCount < retryTimeCount) {
							retryCount++;
							delayTime = (int) (Math.pow(2d, Double.valueOf(retryCount)) * delayTime);
							log.debug("Retry count : " + retryCount + ", Delay Time : " + delayTime + ", Error : "
									+ error);
							Thread.sleep(delayTime);
							return getRefreshTokenByCertificate(oauthconfig);
						} else {
							log.error("Exception occured in client credential: "
									+ Thread.currentThread().getStackTrace()[1].getMethodName()
									+ " Failed to generate the token");
							throw new CustomException(Constants.BAD_REQUEST, "Failed to generate token");
						}
					}
				}
				// logging activity
				log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
						+ "and returning token value");

			} catch (UnirestException | InterruptedException e) {
				log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
						+ " Failed to generate the token");
				throw new CustomException(Constants.BAD_REQUEST, "Failed to generate the token");

			}
			return token;
		}

}
