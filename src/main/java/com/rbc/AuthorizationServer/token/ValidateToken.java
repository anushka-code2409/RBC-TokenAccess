package com.rbc.AuthorizationServer.token;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.stereotype.Service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.rbc.AuthorizationServer.auth.AuthCode;
import com.rbc.AuthorizationServer.config.OAuth2Config;
import com.rbc.AuthorizationServer.config.OAuth2JWKProvider;
import com.rbc.AuthorizationServer.exception.UnauthorizedException;
import com.rbc.AuthorizationServer.utils.Constants;
import com.rbc.AuthorizationServer.utils.TokenGlobals;

/**
 * .SYNOPSIS This class is to check if token object is valid or not
 * 
 * .DESCRIPTION This class consists of validate methods which checks the token
 * response, tokenType, valid resource, access token response nbf and expiry
 * time of the token
 * 
 * .Method isValidToken(), check_expiry()
 * 
 * @author anushkak
 *
 */
@Service
public class ValidateToken {
	private static final int timeSkewAllowance = 300;

	Logger log = LogManager.getLogger(ValidateToken.class);
	OAuth2JWKProvider jwkProvider = new OAuth2JWKProvider();

	@Autowired
	Constants constants;
	AuthCode authCode;

	/**
	 * .SYNOPSIS This method validates the tokenType, resource, accesstoken, nbf
	 * .DESCRIPTION This method checks if token value is present or not, checks
	 * tokenType is bearer or not, checks valid resource is present or not, checks
	 * nbf
	 * 
	 * @param token     to be validated
	 * @param tokenType
	 * @param resource
	 * @return true if token is validated successfully
	 */

	public boolean isValidToken(HashMap<String, String> tokenMetadata, OAuth2Config oauthconfig) {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		if (oauthconfig.getTokenType() == null || oauthconfig.getAudience() == null) {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ " ,Configuration data is null");
			throw new UnauthorizedException(401,"Configuration data is null");
			
		} else {
			hasAccessToken(tokenMetadata);
			hasValidTokenType(tokenMetadata, oauthconfig.getTokenType());
			hasValidResource(tokenMetadata, oauthconfig.getAudience());
			
		}
		// if token is validated successfully
		log.info("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		return true;

	}

	/**
	 * .SYNOPSIS This method validates the whether nbf of token passed has valid
	 * resource .DESCRIPTION This method validates the whether nbf of token passed
	 * has valid resource
	 * 
	 * @param tokenMetadata to be validated
	 */
	private void hasValidResource(HashMap<String, String> tokenMetadata, String resource) {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		// check if valid resource url is present or not
		if (!tokenMetadata.get(Constants.RESOURCE).contains(resource)) {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Invalid resource URL");
			throw new UnauthorizedException(401,"Access token has Invalid resource URL");
		}
		log.info("Token metadata has valid resource url ");
		log.info("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

	}

	/**
	 * .SYNOPSIS This method validates the whether token passed has valid token type
	 * .DESCRIPTION This method validates the whether token passed has valid token
	 * type
	 * 
	 * @param tokenMetadata to be validated
	 */
	private void hasValidTokenType(HashMap<String, String> tokenMetadata, String tokenType) {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		// check for the token type as Bearer
		if (!tokenType.equals(tokenMetadata.get(Constants.TOKEN_TYPE))) {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Invalid Token type ");
			throw new UnauthorizedException(401,"Access token has Invalid Token type");
		}
		log.info("Token type is Bearer");
		log.info("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

	}

	/**
	 * .SYNOPSIS This method validates the whether token passed has Access token
	 * .DESCRIPTION This method validates the whether token passed has Access token
	 * 
	 * @param token to be validated
	 */
	private void hasAccessToken(HashMap<String, String> tokenMetadata) {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		// check if token consists of access token or not
		if (tokenMetadata.get(Constants.ACCESSTOKEN) == null || tokenMetadata.get(Constants.ACCESSTOKEN) == "") {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Token response does not has access_token");
			throw new UnauthorizedException(401,"Token response does not has access_token");
		}
		log.info("Token metadata has access token value ");
		log.info("Exiting function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

	}

	/**
	 * .SYNOPSIS This method checks if token is expired
	 * 
	 * .DESCRIPTION This method gets the current and compares if the expiry time of
	 * token has passed the current time
	 * 
	 * @param token to be validated
	 * @return false if token is not expired
	 */

	public boolean isTokenExpired(JSONObject token)  {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		if (token == null) {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Missing Token value ");
			throw new UnauthorizedException(401,"Missing Token value");
		}
		log.info("Token value is present");

		// get the current time
		Date now = new Date(System.currentTimeMillis() - (timeSkewAllowance * 1000));
		long nowTime = now.getTime();
		// get expires_in time from token metadata
		long expTime = nowTime + (Long.parseLong(token.get(Constants.EXPIRES_IN).toString()));
		Date expiresOn = new Date();
		expiresOn.setTime(expTime * 1000);

		// check if the token expiry time is after current time, or else token is not
		// expired
		if (now.after(expiresOn)) {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ " ,Token is expired");
			throw new UnauthorizedException(401,"Token is expired");
		} else {
			// token is not expired
			log.info("Exiting method: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Token is not expired passing token to resource server ");
			return false;
		}
	}

	/**
	 * .SYNOPSIS This method is used to validate the signature of the decoded token
	 * value using JWKProvider instance and algorithm instance
	 * 
	 * .DESCRIPTION This method validates the signature by jwkProvider interface and
	 * pass the keyId of decoded token value and implement the interface method and
	 * also validate using algorithm instance
	 * 
	 * @param decodedJWT decoded jwt token value
	 * @throws JwkException
	 * @throws InvalidTokenException
	 */
	public boolean hasValidSignature(Object idToken) {

		// logging activity
		log.info("Entering function:" + Thread.currentThread().getStackTrace()[1].getMethodName());

		DecodedJWT decodedJWT = decodeToken(idToken);

		try {
			// jwkProvider interface gets the public URL to fetch JWK(s) and produce java
			// jwk representation of it
			Jwk jwk = jwkProvider.get(decodedJWT.getKeyId());

			// logging activity
			log.info("Extracted JWK: " + jwk);
			// getting a valid RSA256 algorithm using jwk public key
			Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

			// logging activity
			log.info("Extracted Algorithm with the respective jwk public key: " + jwk);
			algorithm.verify(decodedJWT);
			log.info("Token's signature is correct, exiting function :"
					+ Thread.currentThread().getStackTrace()[1].getMethodName());
		} catch (JwkException | SignatureVerificationException ex) {

			// logging activity
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Token has invalid signature");
			throw new UnauthorizedException(401,"Token has invalid signature");
		}
		return true;
	}

	/**
	 * .SYNOPSIS hasValidNonce function is used to validate if the returned idToken
	 * claim, nonce is correct
	 * 
	 * .DESCRIPTION This method gets the current and compares if the expiry time of
	 * token has passed the current time
	 * 
	 * @param token to be validated
	 * @return true if nonce is correct
	 */

	public boolean hasValidNonce(JSONObject token) {
		// logging activity
		log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());

		if (token == null) {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Missing Token value ");
			throw new UnauthorizedException(401,"Missing Token value");
		}
		log.info("Token value is present");

		// getting id token metadata from token object
		String idToken = (String) token.get(Constants.IDTOKEN);
		// decode idToken in JWT
		DecodedJWT decodedJWT = decodeToken(idToken);
		// obtain payload of decoded idToken
		JsonObject payloadAsJson = decodeTokenPayloadToJsonObject(decodedJWT);
		if (payloadAsJson.get(Constants.NONCE).getAsString() == null) {
			throw new UnauthorizedException(401,"Token does not have nonce in payload");
		} else
			// logging activity
			log.info("Extracted Nonce from payload of ID token .. ");
		log.info("Extracted Nonce value passed to generate access token .. ");
		log.info("Exiting method: " + Thread.currentThread().getStackTrace()[1].getMethodName()
				+ ", Id token has valid nonce ");
		return TokenGlobals.globalNonce.equals(payloadAsJson.get(Constants.NONCE).getAsString());

	}

	/**
	 * .SYNOPSIS hasValidState function is used to validate if the returned idToken
	 * claim, nonce is correct
	 * 
	 * .DESCRIPTION This method gets the current and compares if the expiry time of
	 * token has passed the current time
	 * 
	 * @param token to be validated
	 * @return true if state is correct
	 */
	public boolean hasValidState(OAuth2Config oauthconfig) {
		// logging activity
				log.info("Entering function: " + Thread.currentThread().getStackTrace()[1].getMethodName());
		if (!oauthconfig.getState().equals(TokenGlobals.State)) {
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Invalid state ");
			throw new UnauthorizedException(401,"Invalid State");
		}
		// logging activity
		log.info("Exiting method: " + Thread.currentThread().getStackTrace()[1].getMethodName()
				+ ", Token code has valid state ");
		return true;

	}

	/**
	 * .SYNOPSIS This method is used to decode the string access token value
	 * 
	 * .DESCRIPTION This method checks if token value is present, then decode the
	 * string token value to JWT
	 * 
	 * @param value to be decoded
	 * @return decoded JWT token value
	 */
	public DecodedJWT decodeToken(Object idToken) {
		// logging activity
		log.info("Entering function:" + Thread.currentThread().getStackTrace()[1].getMethodName());

		// check if token is not null
		if (idToken == null) {
			throw new InvalidTokenException(" ID Token is missing");
		}
		try {
			// decode the access token value
			DecodedJWT decodedJWT = JWT.decode((String) idToken);

			// logging activity
			log.info("Token decoded successfully, extracted the decoded token value: " + decodedJWT);
			log.info("Exiting function:" + Thread.currentThread().getStackTrace()[1].getMethodName());
			return decodedJWT;
		} catch (Exception e) {
			throw new InvalidTokenException("Token cannot be decoded");
		}
	}

	/**
	 * This method is used to convert decoded Token payload to JSON Object
	 * 
	 * @param decodedJWT
	 * @return JSON object for decoded payload
	 * @throws InvalidTokenException
	 */
	public JsonObject decodeTokenPayloadToJsonObject(DecodedJWT decodedJWT) {
		try {
			// logging activity
			log.info("Entering function:" + Thread.currentThread().getStackTrace()[1].getMethodName());

			// get decoded jwt token value to string
			String payloadAsString = decodedJWT.getPayload();
			// convert string token to json object
			// logging activity
			log.info("Exiting function:" + Thread.currentThread().getStackTrace()[1].getMethodName());
			return new Gson().fromJson(new String(Base64.getDecoder().decode(payloadAsString), StandardCharsets.UTF_8),
					JsonObject.class);
		} catch (RuntimeException exception) {
			// logging activity
			log.error("Exception occured: " + Thread.currentThread().getStackTrace()[1].getMethodName()
					+ ", Invalid JWT or JSON format of each of the jwt parts");

			throw new InvalidTokenException("Invalid JWT or JSON format of each of the jwt parts", exception);
		}
	}

}
