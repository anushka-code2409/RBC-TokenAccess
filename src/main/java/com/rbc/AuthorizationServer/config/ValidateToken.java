package com.rbc.AuthorizationServer.config;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.util.Assert;

import com.mashape.unirest.http.JsonNode;
import com.nimbusds.jose.shaded.json.JSONObject;



public class ValidateToken {
	
	private static final int  timeSkewAllowance = 300;
	
	public static boolean isValidToken(JSONObject token, String tokenType, String resource ) {
		// TODO Auto-generated method stub
		
		if(token == null ) {
			System.out.println("Token response is missing");
			throw new AuthenticationServiceException("Missing Token value");
			
		}
		else
			if(!tokenType.equals(token.get("token_type"))){
				System.out.println("Invalid token type");
				throw new AuthenticationServiceException("Invalid Token type");
					}
			else
				if(!resource.equals(token.get("resource"))) {
					System.out.println("Audience Url is incorrect");
					throw new AuthenticationServiceException("Invalid resource URL");
				}
				else
					if(token.get("access_token")== null || token.get("access_token") == "" ){
						System.out.println("Access token is not present in token");
						throw new AuthenticationServiceException("Token response does not has access_token");
						}
					else {
						return true;
					}		
	}

	
	public static boolean check_expiry( JSONObject token) throws ParseException {
		// TODO Auto-generated method stub
		String expire_on = (String) token.get("expires_on");
		Date now = new Date(System.currentTimeMillis() - (timeSkewAllowance * 1000));
		DateFormat simpleDateFormat=new SimpleDateFormat("yyyy-MM-dd");
		java.sql.Date dutyDay = (java.sql.Date) simpleDateFormat.parse(expire_on);
		if(now.after((Date) dutyDay)) {
			throw new AuthenticationServiceException("Token is expired");
				}
		else {
			return false;
		}
		
	}


	

}
