package com.rbc.AuthorizationServer.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.text.ParseException;
import java.util.HashMap;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import com.rbc.AuthorizationServer.config.OAuth2Config;
import com.rbc.AuthorizationServer.utils.Constants;



/**
 * This is a test class to test the method of class ValidateToken with positive and negative scenario
 * .Methods testMetadataPositive(), testInvalidResource(), testInvalidTokenType(), testNotBeforeTime(),testCheck_expiry()
 * @author anushkak
 *
 */
 public class ValidateTokenUnitTest {
	
ValidateToken object = new ValidateToken();
OAuth2Config oauthConfig = new OAuth2Config();
	
	
	@Test  
	   void testMetadataPositive()  { 
		//testing positive scenarios
		HashMap<String, String> token = new HashMap<String,String>();
		token.put(Constants.ACCESSTOKEN,"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w");
		token.put(Constants.RESOURCE,"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put(Constants.TOKEN_TYPE,"Bearer");
		
		oauthConfig.setTokenType("Bearer");
		oauthConfig.setAudience("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		
		boolean result = object.isValidToken(token,oauthConfig);
		
		assertEquals(true,result);
	}
	
	@Test  
	   void testMetadataNegative()  { 
		//testing negative scenarios
		HashMap<String, String> token = new HashMap<String,String>();
		token.put(Constants.ACCESSTOKEN,"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w");
		token.put(Constants.RESOURCE,"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put(Constants.TOKEN_TYPE,"Bearer");
		
		oauthConfig.setTokenType(null);
		oauthConfig.setAudience("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.isValidToken(token,oauthConfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "Configuration data is null";
		assertEquals(expectedMessage,result);
	}
	@Test  
	   void testMetadataNegativeScenario()  { 
		//testing negative scenarios
		HashMap<String, String> token = new HashMap<String,String>();
		token.put(Constants.ACCESSTOKEN,"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w");
		token.put(Constants.RESOURCE,"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put(Constants.TOKEN_TYPE,"Bearer");
		
		oauthConfig.setTokenType("Bearer");
		oauthConfig.setAudience(null);
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.isValidToken(token,oauthConfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "Configuration data is null";
		assertEquals(expectedMessage,result);
	}
	
	@Test  
	   void testInvalidResource()  { 
		//testing negative scenario by passing invalid resource
		HashMap<String, String> token = new HashMap<String,String>();
		token.put(Constants.ACCESSTOKEN,"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w");
		token.put(Constants.RESOURCE,"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put(Constants.TOKEN_TYPE,"Bearer");
		
		oauthConfig.setTokenType("Bearer");
		oauthConfig.setAudience("hdkahkh");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.isValidToken(token,oauthConfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "Access token has Invalid resource URL";
		assertEquals(expectedMessage,result,"Failed by passing invalid token type");
	}
	
	@Test  
	   void testInvalidTokenType()  { 
		//testing negative scenario by passing invalid token type
		HashMap<String, String> token = new HashMap<String,String>();
		token.put(Constants.ACCESSTOKEN,"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w");
		token.put(Constants.RESOURCE,"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put(Constants.TOKEN_TYPE,"Bearer");
		
		oauthConfig.setTokenType("JWT");
		oauthConfig.setAudience("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.isValidToken(token,oauthConfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "Access token has Invalid Token type";
		assertEquals(expectedMessage,result,"Failed by passing invalid token type");
	}
	
	@Test  
	   void testHasAccessToken()  { 
		//testing negative scenario by passing nbf with future date
		HashMap<String, String> token = new HashMap<String,String>();
		token.put(Constants.ACCESSTOKEN,null);
		token.put(Constants.RESOURCE,"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put(Constants.TOKEN_TYPE,"Bearer");
		
		oauthConfig.setTokenType("Bearer");
		oauthConfig.setAudience("api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.isValidToken(token,oauthConfig);
		    });
		
		String result = exception.getMessage();
		String expectedMessage = "Token response does not has access_token";
		assertEquals(expectedMessage,result,"Failed by passing access token");
	}
	

	@Test  
	   void testIsTokenExpired() throws ParseException  { 
		//testing negative scenario by passing token with expired time
		JSONObject token = new JSONObject();
		token.put("access_token","eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w");
		token.put("resource","api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put("token_type","Bearer");
		token.put("expires_in","3599");
		
		boolean result = object.isTokenExpired(token);
		assertEquals(false,result,"Failed by token with expired time");
	}
	@Test  
	   void testNegativeIsTokenExpired() throws ParseException  { 
		//testing negative scenario by passing token with expired time
		JSONObject token = new JSONObject();
		token.put("access_token","eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w");
		token.put("resource","api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put("token_type","Bearer");
		token.put("expires_in","35");
			
		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			 object.isTokenExpired(token);
		    });
	
		String expectedMessage = "Token is expired";
		String result = exception.getMessage();
		assertEquals(expectedMessage,result,"Failed by token with expired time");
	}
	
	@Test  
	   void testHasValidNonceNegative()  { 
		//testing negative scenario by passing token with expired time
		JSONObject token = new JSONObject();
		token.put(Constants.IDTOKEN,"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly81ZDdlN2ZhMC0yYzdhLTQyZjQtYjViOC04ODdlMDBhZTk4MGEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjYwNjQ4MDMwLCJuYmYiOjE2NjA2NDgwMzAsImV4cCI6MTY2MDY1MTkzMCwiYWlvIjoiRTJaZ1lJZ3MrdkhlLzBhN3V0TGZqVFBXTXJ4OUN3QT0iLCJhcHBpZCI6IjE5OTVlYWZkLTVjYmMtNDAzMC1hZmQwLWIwOTRlMDc2ZWU5NyIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzRkZTZhNzg0LWU4NzQtNGY3Ni1iYmJlLWEzMzgyZTA0ZWMyOS8iLCJvaWQiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJyaCI6IjAuQVZVQWhLZm1UWFRvZGstN3ZxTTRMZ1RzS2FCX2ZsMTZMUFJDdGJpSWZnQ3VtQXFJQUFBLiIsInJvbGVzIjpbIkV4YW1wbGUiLCJUZXN0Um9sZSJdLCJzdWIiOiI0NTZiN2IxNi03Y2ZjLTQzNjYtOTM1Zi1lMWJkMWFlZGMwMzYiLCJ0aWQiOiI0ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkiLCJ1dGkiOiJrbUh0NzhJZ05FbUNZNE5LTVVGdUFBIiwidmVyIjoiMS4wIn0.Q-7pNhvTw4KCWBvNmvgk5GGv3Q1Qb6EZDt-EvOlpSwHUEs4FJyCL8q3ySBaTpPwTID2qlJbXhfAfxgR8hDhfgB8aQxM-TWNYTptERAGBAdzuYhsXm7h8CaLWWFQM9Jhf8yKE71VYxevFjV4raXWEhGIeoqpPp_hE5zirqgDFqNQ-r9DVHLqHYD_FxN9vsSf5ytQ5aEYugniL1Z4mxRyXtPu8twNehWKQraC-MLEF4saLacWy-ueA8fi2Fttz7ycd2IJsyRP7gyWEklGvfvMUwtt8fh5u0IHO_7Ch111x2AEdi5mu3uUef28f2JZc1vAuqyZc4bwqHjQI-ht-Wmi13w");
		token.put("resource","api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put("ext_expires_in","3599");
		token.put("token_type","Bearer");
		token.put("expires_in","3599");

		Exception exception = assertThrows(InvalidTokenException.class, () -> {
			 object.hasValidNonce(token);
		    });
	
		String expectedMessage = "Token does not have nonce in payload";
		String result = exception.getMessage();
		assertEquals(expectedMessage,result,"Failed by token with expired time");
	}
	@Test  
	   void testHasValidSignature()  { 
		//testing negative scenario by passing token with expired time
		JSONObject token = new JSONObject();
		token.put(Constants.IDTOKEN,"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiIxOTk1ZWFmZC01Y2JjLTQwMzAtYWZkMC1iMDk0ZTA3NmVlOTciLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC80ZGU2YTc4NC1lODc0LTRmNzYtYmJiZS1hMzM4MmUwNGVjMjkvIiwiaWF0IjoxNjY0NDIzMDI1LCJuYmYiOjE2NjQ0MjMwMjUsImV4cCI6MTY2NDQyNjkyNSwiYW1yIjpbInB3ZCJdLCJpcGFkZHIiOiIxMDMuMTEwLjE5NS4xMDIiLCJuYW1lIjoiVGVzdCBVc2VyIiwibm9uY2UiOiI5OTJmODY1NTM0ZmNkMDVmM2YzNjA1YjQ3NTY3Njc3YWFiMzI1MDFiIiwib2lkIjoiY2IxOThiNDctYWMyNi00NDZlLWFhM2MtMGE0NzIyOGYyMGYxIiwicmgiOiIwLkFWVUFoS2ZtVFhUb2RrLTd2cU00TGdUc0tmM3FsUm04WERCQXI5Q3dsT0IyN3BlSUFOZy4iLCJzdWIiOiJ5dXdqbkxlN3ZrOEdYOGJ2OVludjhQbC1hSGZmeHJERGh2dFM5eERMQlUwIiwidGlkIjoiNGRlNmE3ODQtZTg3NC00Zjc2LWJiYmUtYTMzODJlMDRlYzI5IiwidW5pcXVlX25hbWUiOiJ0ZXN0dXNlcjJAZGtyYnlhaG9vLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6InRlc3R1c2VyMkBka3JieWFob28ub25taWNyb3NvZnQuY29tIiwidXRpIjoia3p5OXRwUThXRS1uaDlnTXltVVNBQSIsInZlciI6IjEuMCJ9.vZ3y0xELY6MjWmwjnAj2IzYir9RD-L8IsCU4mHrvoQBWI3KFF1DSKcRtdfxkBSEgIrhlZVoVmQXVT-wlSEYZUy2o-gChar3j8aD-W9iGbnjS5RBlqd5dd2F6M1cqKpOcy6MVhjJL6QuZBOo-Xmxcfw3lSVy1Zh8pgERfvAuTjiXazA0JqNSldbYHQR7QSUNt_np-jSrlhc8NNJNc-j-dOCffli4J0PdSFFxWb8trs9QfJAJyKnAlZ-KcnK5rkYyYwMEk064oL-wIha1qcs0PqvdEDWF99xTzafL8tIXAnp8sB_KQs65UVcfop1OkpKbujlIzdqnS3t8Su43AbZrMGQ");
		token.put("resource","api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a");
		token.put("ext_expires_in","3599");
		token.put("token_type","Bearer");
		token.put("expires_in","3599");

		boolean result = object.hasValidSignature(token);
		assertEquals(true,result,"Failed by token with invalid signature");
	}

}
