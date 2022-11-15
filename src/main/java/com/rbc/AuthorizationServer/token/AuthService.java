package com.rbc.AuthorizationServer.token;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import com.mashape.unirest.http.exceptions.UnirestException;
import com.rbc.AuthorizationServer.auth.AuthCode;
import com.rbc.AuthorizationServer.config.OAuth2Config;
import com.rbc.AuthorizationServer.config.OAuth2JWKProvider;
import com.rbc.AuthorizationServer.utils.Constants;
import com.rbc.AuthorizationServer.utils.TokenGlobals;
import com.rbc.AuthorizationServer.utils.Utility;

public class AuthService {

	// declaration of all global variables
	// Creating HashMap for token metadata and response metadata
	HashMap<String, String> tokenMetadata = new HashMap<String, String>();
	JSONObject responseMetadata = new JSONObject();
	// instantiating classes to call the custom functions to generate, validate
	// token
	OAuth2Config oauthconfig = new OAuth2Config();
	ValidateToken validateToken = new ValidateToken();
	AuthCode authCode = new AuthCode();
	OAuth2JWKProvider provider = new OAuth2JWKProvider();

	Logger log = LogManager.getLogger(AuthService.class);

	/**
	 * .SYNOPSIS This method is gets the codeUri to string value .DESCRIPTION The
	 * method calls the custom function to get the code uri in string value
	 * 
	 * @param clientProperty
	 * @return string code url value
	 */
	public String getCodeURI(Properties clientProperty) {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		oauthconfig.setCodeChallengeUri(clientProperty.getProperty("auth.CodeChallengeUri"));
		oauthconfig.setClientId(clientProperty.getProperty("auth.clientId"));
		oauthconfig.setCodeResponseType(clientProperty.getProperty("auth.CodeResponseType"));
		oauthconfig.setRedirectUri(clientProperty.getProperty("auth.RedirectUri"));
		oauthconfig.setScope(clientProperty.getProperty("auth.Scope"));
		oauthconfig.setFingerprint(clientProperty.getProperty("fingerprint"));
		oauthconfig.setSessionId(clientProperty.getProperty("sessionId"));
		String codeUri = "";

		try {
			// calling custom method to generate code url
			codeUri = authCode.generateCodeUrl(oauthconfig);
		} catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {

			throw new AuthenticationServiceException("Failed to generate Code url");
		}
		// logging activity
		log.info("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
				+ " and returning codeUrl: " + codeUri);
		return codeUri;

	}

	/**
	 * .SYNOPSIS This method is used to get the token value and validate the
	 * metadata of the token .DESCRIPTION This method calls the custom method which
	 * gets the token value and validate the metadata of the token
	 * 
	 * @param clientProperty
	 * @return token if validated successfully
	 * 
	 */
	public JSONObject getTokenResponse(Properties clientProperty, boolean isRefreshToken) {
		oauthconfig.setFingerprint(clientProperty.getProperty("fingerprint"));
		oauthconfig.setSessionId(clientProperty.getProperty("sessionId"));
		oauthconfig.setEncryptionKey(clientProperty.getProperty("auth.EncryptionKey"));
		oauthconfig.setIpAddress(clientProperty.getProperty("ipAddress"));
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		boolean getToken = getAuthToken(clientProperty, isRefreshToken);
		boolean isValidToken = true;
		// check if getToken method returns true, i.e token is present and then validate
		// token's metadata
		if (getToken) {
			log.debug("Checking if token metadata is validated successfully..");
			isValidToken = validateToken.isValidToken(tokenMetadata, oauthconfig)
					&& validateToken.hasValidNonce(TokenGlobals.tokenMeta) && TokenGlobals.idToken != null;

			// return token if token is valid
			if (isValidToken) {

				responseMetadata = getTokenResponse(oauthconfig);
			} else {
				log.error("Exception occured at: " + Thread.currentThread().getStackTrace()[1].getMethodName());
				throw new InvalidTokenException("Token is not validated successfully");
			}
			// logging activity
			log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ " and returning token value..");

		}
		return responseMetadata;

	}

	/**
	 * 
	 * @param clientProperty
	 * @return responseMetadata
	 */
	public JSONObject getSessionToken(Properties clientProperty) {
		oauthconfig.setTokenType(clientProperty.getProperty("auth.tokenType"));
		oauthconfig.setAudience(clientProperty.getProperty("auth.audience"));
		oauthconfig.setFingerprint(clientProperty.getProperty("fingerprint"));
		oauthconfig.setSessionId(clientProperty.getProperty("sessionId"));
		oauthconfig.setEncryptionKey(clientProperty.getProperty("auth.EncryptionKey"));
		oauthconfig.setIpAddress(clientProperty.getProperty("ipAddress"));
		oauthconfig.setClientId(clientProperty.getProperty("auth.clientId"));
		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		tokenMetadata.put(Constants.ACCESSTOKEN, (String) TokenGlobals.tokenMeta.get(Constants.ACCESSTOKEN));
		tokenMetadata.put(Constants.IDTOKEN, (String) TokenGlobals.tokenMeta.get(Constants.IDTOKEN));
		tokenMetadata.put(Constants.RESOURCE, (String) TokenGlobals.tokenMeta.get(Constants.SCOPE));
		tokenMetadata.put(Constants.TOKEN_TYPE, (String) TokenGlobals.tokenMeta.get(Constants.TOKEN_TYPE));
		tokenMetadata.put(Constants.EXPIRES_IN, TokenGlobals.tokenMeta.get(Constants.EXPIRES_IN).toString());

		boolean isValidToken = validateToken.isValidToken(tokenMetadata, oauthconfig);

		if (isValidToken) {
			responseMetadata = getTokenResponse(oauthconfig);
		}

		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		return responseMetadata;

	}

	/**
	 * .SYNOPSIS This method is created to call the custom functions to generate
	 * access token using auth code + pkce pattern, validate it and call resource
	 * api .DESCRIPTION This method first calls the method to generate token using
	 * auth code + pkce pattern, if also token value is null or gets expired, then
	 * validates its metadata and if everything is validated successfully then calls
	 * resource api
	 * 
	 * @return true if token is validated successfully
	 * @throws ParseException
	 * @throws UnirestException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public boolean getAuthToken(Properties clientProperty, boolean isRefreshToken) {

		// logging activity
		log.debug("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		// setting properties value from stubApp to oauthconfig object
		oauthconfig.setClientId(clientProperty.getProperty("auth.clientId"));
		oauthconfig.setGrantType(clientProperty.getProperty("auth.grantType"));
		oauthconfig.setRedirectUri(clientProperty.getProperty("auth.RedirectUri"));
		oauthconfig.setTokenUrl(clientProperty.getProperty("auth.tokenUrl"));
		oauthconfig.setClientSecret(clientProperty.getProperty("auth.clientSecret"));
		oauthconfig.setTenantId(clientProperty.getProperty("auth.tenantId"));
		oauthconfig.setGrantType(clientProperty.getProperty("auth.grantType"));
		oauthconfig.setScope(clientProperty.getProperty("auth.Scope"));
		oauthconfig.setTokenType(clientProperty.getProperty("auth.tokenType"));
		oauthconfig.setAudience(clientProperty.getProperty("auth.audience"));
		oauthconfig.setCodeChallangeMethodAlg(clientProperty.getProperty("auth.CodeChallangeMethodAlg"));
		oauthconfig.setClientAssertionType(clientProperty.getProperty("auth.ClientAssertionType"));
		oauthconfig.setCredentialType(clientProperty.getProperty("auth.CredentialType"));
		oauthconfig.setIssuer(clientProperty.getProperty("auth.Issuer"));
		oauthconfig.setThumbprint(clientProperty.getProperty("auth.Thumbprint"));
		oauthconfig.setPublicKey(clientProperty.getProperty("auth.PublicKey"));
		oauthconfig.setPrivateKey(clientProperty.getProperty("auth.PrivateKey"));
		oauthconfig.setJwksUri(clientProperty.getProperty("auth.jwksUri"));
		oauthconfig.setRetryDelayTime(clientProperty.getProperty("auth.RetryDelayTime"));
		oauthconfig.setRetryCount(clientProperty.getProperty("auth.RetryCount"));
		oauthconfig.setRetryExceptions(clientProperty.getProperty("auth.RetryExceptions"));
		oauthconfig.setCode(clientProperty.getProperty("code"));
		oauthconfig.setState(clientProperty.getProperty("state"));

		String jwksUri = oauthconfig.getJwksUri();
		provider.getJwkUrl(jwksUri);

		String jsonToken = null;

		if (!isRefreshToken) {
			// call custom method getAccessToken to generate token and even after access
			// token value is null or gets expired
			if (validateToken.hasValidState(oauthconfig)) {
				if (TokenGlobals.accessToken == null) {
					// get the string token value according to the credential type
					if (oauthconfig.getCredentialType().toUpperCase().equals(Constants.SECRET)) {
						// getting access token by secret
						jsonToken = authCode.getAccessTokenBySecret(oauthconfig);

					} else {
						// getting access token by certificate
						jsonToken = authCode.getAccessTokenByCertificate(oauthconfig);
					}
				}
				if (jsonToken != null) {
					TokenGlobals.tokenMeta = new JSONObject(jsonToken);
					TokenGlobals.idToken = TokenGlobals.tokenMeta.get(Constants.IDTOKEN);
					// getting token metadata into hashpmap
					tokenMetadata.put(Constants.ACCESSTOKEN,
							(String) TokenGlobals.tokenMeta.get(Constants.ACCESSTOKEN));
					tokenMetadata.put(Constants.IDTOKEN, (String) TokenGlobals.tokenMeta.get(Constants.IDTOKEN));
					tokenMetadata.put(Constants.RESOURCE, (String) TokenGlobals.tokenMeta.get(Constants.SCOPE));
					tokenMetadata.put(Constants.TOKEN_TYPE, (String) TokenGlobals.tokenMeta.get(Constants.TOKEN_TYPE));
					tokenMetadata.put(Constants.EXPIRES_IN,
							TokenGlobals.tokenMeta.get(Constants.EXPIRES_IN).toString());

					log.info("Checking if Id token is not null and token has valid signature");
					return TokenGlobals.idToken != null && validateToken.hasValidSignature(TokenGlobals.idToken);
				}
			}
		} else {
			// getting refresh token from token metadata
			TokenGlobals.refreshToken = TokenGlobals.tokenMeta.get(Constants.REFRESHTOKEN).toString();
			log.info("Token is expired and need to get token using refresh token");
			if (oauthconfig.getCredentialType().toUpperCase().equals(Constants.SECRET)) {

				jsonToken = authCode.getRefreshTokenBySecret(oauthconfig);
			} else {
				jsonToken = authCode.getRefreshTokenByCertificate(oauthconfig);
			}
			if (jsonToken != null) {
				TokenGlobals.tokenMeta = new JSONObject(jsonToken);
				TokenGlobals.idToken = TokenGlobals.tokenMeta.get(Constants.IDTOKEN);
				// getting token metadata into hashpmap
				tokenMetadata.put(Constants.ACCESSTOKEN, (String) TokenGlobals.tokenMeta.get(Constants.ACCESSTOKEN));
				tokenMetadata.put(Constants.IDTOKEN, (String) TokenGlobals.tokenMeta.get(Constants.IDTOKEN));
				tokenMetadata.put(Constants.RESOURCE, (String) TokenGlobals.tokenMeta.get(Constants.SCOPE));
				tokenMetadata.put(Constants.TOKEN_TYPE, (String) TokenGlobals.tokenMeta.get(Constants.TOKEN_TYPE));
				tokenMetadata.put(Constants.EXPIRES_IN, TokenGlobals.tokenMeta.get(Constants.EXPIRES_IN).toString());

				log.info("Checking if Id token is not null and token has valid signature");
				return TokenGlobals.idToken != null && validateToken.hasValidSignature(TokenGlobals.idToken);
			}

		}
		// logging activity
		log.debug("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		return true;
	}

	/**
	 * 
	 * @param oauthconfig
	 * @return
	 */
	public JSONObject getTokenResponse(OAuth2Config oauthconfig) {

		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		String stringToHash = "";
		Utility utility = new Utility();

		String encryptedAccessToken = utility.encryptString(tokenMetadata.get(Constants.ACCESSTOKEN),
				oauthconfig.getEncryptionKey());

		if (oauthconfig.getIpAddress() != null) {
			stringToHash = tokenMetadata.get(Constants.ACCESSTOKEN).concat(oauthconfig.getIpAddress())
					.concat(oauthconfig.getFingerprint());
		} else {
			stringToHash = tokenMetadata.get(Constants.ACCESSTOKEN).concat(oauthconfig.getFingerprint());
		}

		String encryptedHash = utility.getHashString(stringToHash);

		Calendar calendar = Calendar.getInstance();
		// get expires_in time from token metadata
		int expInTime =  (int) (Long.parseLong(tokenMetadata.get(Constants.EXPIRES_IN)));
		calendar.add(Calendar.SECOND, expInTime);
		Date expOnTime = calendar.getTime();
		responseMetadata.put(Constants.ENCRYPTED_ACCESS_TOKEN, encryptedAccessToken);
		responseMetadata.put(Constants.ENCRYPTED_HASH, encryptedHash);
		responseMetadata.put(Constants.SCOPE_API, tokenMetadata.get(Constants.RESOURCE));
		responseMetadata.put(Constants.EXPIRY_TIME, expOnTime);
		responseMetadata.put(Constants.CLIENTID, oauthconfig.getClientId());
		responseMetadata.put(Constants.ID_TOKEN, tokenMetadata.get(Constants.IDTOKEN));

		// logging activity
		log.info("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		return responseMetadata;

	}
}
