package com.rbc.AuthorizationServer.config;

import java.text.ParseException;
import java.util.Date;
import org.springframework.security.authentication.AuthenticationServiceException;
import com.nimbusds.jose.shaded.json.JSONObject;

/**
 * .SYNOPSIS
 * This class is to check if token object is valid or not
 * .DESCRIPTION
 * This class consists of validate methods which checks the token response, tokenType, valid resource, access token response
 * nbf and expiry time of the token
 * @author anushkak
 *
 */

public class ValidateToken {
	
	private static final int  timeSkewAllowance = 300;
	
	public static boolean isValidToken(JSONObject token, String tokenType, String resource ) {
		// TODO Auto-generated method stub
		// check the token response if present or not
		if(token == null ) {
			System.out.println("Token response is missing");
			throw new AuthenticationServiceException("Missing Token value");
			
		}
		// check for the token type as Bearer
		else
			if(!tokenType.equals(token.get("token_type"))){
				System.out.println("Invalid token type");
				throw new AuthenticationServiceException("Invalid Token type");
					}
		// check if valid resource url is present or not
			else
				if(!resource.equals(token.get("resource"))) {
					System.out.println("Audience Url is incorrect");
					throw new AuthenticationServiceException("Invalid resource URL");
				}
		// check if token consists of access token or not
				else
					if(token.get("access_token")== null || token.get("access_token") == "" ){
						System.out.println("Access token is not present in token");
						throw new AuthenticationServiceException("Token response does not has access_token");
						}
		// check for token nbf
					else
						if(token.get("not_before")!= null) {
							Date now = new Date(System.currentTimeMillis() + (timeSkewAllowance * 1000));
							long exp_time = Long.parseLong( (String) token.get("not_before"));
							Date expires_on = new Date();
							expires_on.setTime(exp_time * 1000);
							if(now.before((Date)expires_on )) {
								throw new AuthenticationServiceException("Access token is not valid until:" + token.get("not_before"));
							}
						}
					
		
		return true;		
	}

	
	/**
	 * 
	 * check if token is expired
	 */
	
	public static boolean check_expiry( JSONObject token) throws ParseException {
		// TODO Auto-generated method stub
		Date now = new Date(System.currentTimeMillis() - (timeSkewAllowance * 1000));
		long exp_time = Long.parseLong( (String) token.get("expires_on"));
		Date expires_on = new Date();
		expires_on.setTime(exp_time * 1000);	
				if(now.after((Date)expires_on )) {
			throw new AuthenticationServiceException("Token is expired");
				}else {
			return false;
		}
		
	}
}


	


