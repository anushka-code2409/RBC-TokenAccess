package com.rbc.AuthorizationServer.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.rbc.AuthorizationServer.config.OAuth2Config;

public class ClientCredentialUnitTest {

	
	ClientCredential object = new ClientCredential();
	OAuth2Config oauthconfig = new OAuth2Config();
	
//	@Test  
//     void testgetAccessToken() throws UnirestException{  
//       
//		String expected =  "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w\",\"resource\":\"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a\",\"not_before\":\"1660648030\",\"expires_on\":\"1660651930\",\"ext_expires_in\":\"3599\",\"token_type\":\"Bearer\",\"expires_in\":\"3599\"}\r\n";
//		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
//		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
//		oauthconfig.setGrantType("client_credentials");
//		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
//		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
//		
//		String result = object.getAccessToken(oauthconfig);
//        assertEquals(expected,result);  
//       
//    }  
	@Test  
    void testGetAccessTokenConfig1() {  
      
		oauthconfig.setClientId(null) ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessToken(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "clientId required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	@Test  
    void testGetAccessTokenConfig2() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret(null);
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessToken(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "clientSecret required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	@Test  
    void testGetAccessTokenConfig3() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType(null);
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessToken(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "grantType required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	@Test  
    void testGetAccessTokenConfig4() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl(null);
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessToken(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "tokenUrl required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	
	@Test  
    void testGetAccessTokenConfig5() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope(null);
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessToken(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "scope required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
//	@Test  
//     void testgetAccessTokenByCertificate() throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, UnirestException, IOException {  
//       
//		String expected =  "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w\",\"resource\":\"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a\",\"not_before\":\"1660648030\",\"expires_on\":\"1660651930\",\"ext_expires_in\":\"3599\",\"token_type\":\"Bearer\",\"expires_in\":\"3599\"}\r\n";
//		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
//		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
//		oauthconfig.setGrantType("client_credentials");
//		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
//		oauthconfig.setClientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
//		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
//		
//		
//		String result = object.getAccessTokenByCertificate(oauthconfig);
//        assertEquals(expected,result);  
//       
//    }  
	
	@Test  
    void testGetAccessTokenByCertificateConfig1() {  
      
		oauthconfig.setClientId(null) ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		oauthconfig.setClientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessTokenByCertificate(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "clientId required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	@Test  
    void testGetAccessTokenByCertificateConfig2() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret(null);
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		oauthconfig.setClientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessTokenByCertificate(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "clientSecret required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	@Test  
    void testGetAccessTokenByCertificateConfig3() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType(null);
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		oauthconfig.setClientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessTokenByCertificate(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "grantType required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	@Test  
    void testGetAccessTokenByCertificateConfig4() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl(null);
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		oauthconfig.setClientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessTokenByCertificate(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "tokenUrl required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	
	@Test  
    void testGetAccessTokenByCertificateConfig5() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope(null);
		oauthconfig.setClientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessTokenByCertificate(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "scope required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  
	@Test  
    void testGetAccessTokenByCertificateConfig6() {  
      
		oauthconfig.setClientId("1995eafd-5cbc-4030-afd0-b094e076ee97") ;
		oauthconfig.setClientSecret("Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid");
		oauthconfig.setGrantType("client_credentials");
		oauthconfig.setTokenUrl("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/token");
		oauthconfig.setScope("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default offline_access openid");
		oauthconfig.setClientAssertionType(null);
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.getAccessTokenByCertificate(oauthconfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "ClientAssertionType required cannot be null";
		assertEquals(expectedMessage,result);  
      
   }  

}
