package com.rbc.AuthorizationServer.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.rbc.AuthorizationServer.config.OAuth2Config;

public class AuthCodeUnitTest {
	AuthCode object = new AuthCode();
	OAuth2Config oauthconfig = new OAuth2Config();
	

	@Test  
	  void testgenerateCodeUrlConfig1() throws UnsupportedEncodingException, NoSuchAlgorithmException {  
	    
			oauthconfig.setClientId(null) ;
			oauthconfig.setCodeChallengeUri("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/authorize");
			oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
			oauthconfig.setCodeResponseType("code");
			oauthconfig.setRedirectUri("http://localhost:8080/StubApplication/ConfidentialClient");
			
			Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
				 object.generateCodeUrl(oauthconfig);
			    });
			
			String result = exception.getMessage();
			String expectedMessage = "clientId required cannot be null";
			assertEquals(expectedMessage,result);  
	    
	 }
	@Test  
	  void testgenerateCodeUrlConfig2() throws UnsupportedEncodingException, NoSuchAlgorithmException {  
	    
			oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
			oauthconfig.setCodeChallengeUri(null);
			oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
			oauthconfig.setCodeResponseType("code");
			oauthconfig.setRedirectUri("http://localhost:8080/StubApplication/ConfidentialClient");
			
			Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
				 object.generateCodeUrl(oauthconfig);
			    });
			
			String result = exception.getMessage();
			String expectedMessage = "codeChallengeUri required cannot be null";
			assertEquals(expectedMessage,result);  
	    
	 }
	@Test  
	  void testgenerateCodeUrlConfig3() throws UnsupportedEncodingException, NoSuchAlgorithmException {  
	    
			oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
			oauthconfig.setCodeChallengeUri("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/authorize");
			oauthconfig.setScope(null);
			oauthconfig.setCodeResponseType("code");
			oauthconfig.setRedirectUri("http://localhost:8080/StubApplication/ConfidentialClient");
			
			Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
				 object.generateCodeUrl(oauthconfig);
			    });
			
			String result = exception.getMessage();
			String expectedMessage = "scope required cannot be null";
			assertEquals(expectedMessage,result);  
	    
	 }
	@Test  
	  void testgenerateCodeUrlConfig4() throws UnsupportedEncodingException, NoSuchAlgorithmException {  
	    
			oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
			oauthconfig.setCodeChallengeUri("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/authorize");
			oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
			oauthconfig.setCodeResponseType(null);
			oauthconfig.setRedirectUri("http://localhost:8080/StubApplication/ConfidentialClient");
			
			Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
				 object.generateCodeUrl(oauthconfig);
			    });
			
			String result = exception.getMessage();
			String expectedMessage = "codeResponseType required cannot be null";
			assertEquals(expectedMessage,result);  
	    
	 }
	@Test  
	  void testgenerateCodeUrlConfig5() throws UnsupportedEncodingException, NoSuchAlgorithmException {  
	    
			oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
			oauthconfig.setCodeChallengeUri("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/authorize");
			oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
			oauthconfig.setCodeResponseType("code");
			oauthconfig.setRedirectUri(null);
			
			Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
				 object.generateCodeUrl(oauthconfig);
			    });
			
			String result = exception.getMessage();
			String expectedMessage = "redirectUri required cannot be null";
			assertEquals(expectedMessage,result);  
	    
	 }

}
