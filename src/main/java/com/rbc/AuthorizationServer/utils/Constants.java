package com.rbc.AuthorizationServer.utils;

import org.apache.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class Constants {

	private Constants() {}
	
	public static final String NOT_BEFORE = "not_before";
	public static final String EXPIRES_IN = "expires_in";
	public static final String RESOURCE = "resource";
	public static final String ENCRYPTED_ACCESS_TOKEN = "AccessToken";
	public static final String ENCRYPTED_HASH = "EncryptedHash";
	public static final String EXPIRES_ON = "expiresOn";
	public static final String EXPIRY_TIME = "ExpiryTime";
	public static final String TOKEN_TYPE = "token_type";
	public static final String ACCESSTOKEN = "access_token";
	public static final String RS256 = "RS256";
	public static final String JWT = "JWT";
	public static final String SECRET = "SECRET";
	public  static final String CLIENT_ID = "client_id";
	public  static final String CLIENTID = "ClientId";
	public  static final String RESPONSE_TYPE = "response_type";
	public  static final String CODE_RESPONSE_TYPE = "code";
	public  static final String REDIRECT_URI = "redirect_uri";
	public  static final String SCOPE = "scope";
	public  static final String SCOPE_API = "Scope";
	public  static final String CODE_CHALLENGE = "code_challenge";
	public  static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
	public  static final String CODE_CHALLENGE_METHOD_ALG = "S256";
	public  static final String CODE_VERIFIER = "code_verifier";
	public  static final String NONCE = "nonce";
	public  static final String STATE = "state";
	public static final String IDTOKEN = "id_token";
	public static final String ID_TOKEN = "IdToken";
	public static final String REFRESHTOKEN = "refresh_token";
	public static final String KEYS = "keys";
	public static final String RSA = "RSA";
	public static final String X509 = "X.509";
	public static final String ALGORITHM = "alg";
	public static final String TYPE = "typ";
	public static final String X5T = "x5t";
	public static final String SHA1 = "SHA-1";
    public static final String SSL = "SSL";
    public static final String RBC_PROXY ="oproxy.fg.rbc.com";
    public static final int RBC_PROXY_PORT_Number =8080;
    public static final String SHA256 = "SHA-256";
    public static final String USASCII ="US-ASCII";
    public static final String SHA1PRNG = "SHA1PRNG";
    public static final String UTF8 = "UTF-8";
    public static final int UNAUTHORIZED = HttpStatus.SC_UNAUTHORIZED;
    public static final int BAD_REQUEST = HttpStatus.SC_BAD_REQUEST;
    public static final int NOT_FOUND = HttpStatus.SC_NOT_FOUND;
    public static final String STATUSCODE401 = "401";
    public static final String STATUSCODE400 = "400";
    public static final String STATUSCODENOT_FOUND = "NOT_FOUND";
    public static final String ERROR = "error";
    public static final String RETRYAFTER = "retryafter";

}
