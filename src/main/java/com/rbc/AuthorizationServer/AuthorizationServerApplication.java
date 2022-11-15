package com.rbc.AuthorizationServer;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.web.bind.annotation.RestController;



/**
 * .SYNOPSIS
 * This class is main class and is created to run the spring boot application for generating the token value and passing the token value to resource server for token validation
 * 
 * .DESCRIPTION
 * This class is main class and is created to run the spring boot application for generating the token value and passing the token value to resource server for token validation
 * this class has main() method which runs the spring boot application
 * 
 * .Methods
 * main()
 * @author anushkak
 *
 */
@RestController
@SpringBootApplication


public class AuthorizationServerApplication {
	
	public static void main(String[] args)   {
		SpringApplication.run(AuthorizationServerApplication.class, args);
		
		
		String resource = "api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a";
		String tokenType = "Bearer";
			
	    String json_token = AuthorizationServer.getAccessToken();     
	    JSONParser parser = new JSONParser();
	    JSONObject token = (JSONObject) parser.parse(json_token);
	    System.out.println(token);

	    boolean is_valid_token = ValidateToken.isValidToken(token, tokenType, resource);
	    
	    //if token is valid, then check if token is expired
	    try {
			if(is_valid_token==true) {
				System.out.println("Token is valid");
				//check if token is expired
				boolean is_token_expire = ValidateToken.check_expiry(token);
				
				if(is_token_expire == false) {
					//call resource server api
				}
				else {
					System.out.println("Token is expired");
				}
			}
		} catch (java.text.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	

}
