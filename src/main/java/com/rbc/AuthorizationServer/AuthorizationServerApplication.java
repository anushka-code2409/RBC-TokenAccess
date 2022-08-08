package com.rbc.AuthorizationServer;

import java.io.IOException;
import java.net.MalformedURLException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.RestController;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.shaded.json.parser.JSONParser;
import com.nimbusds.jose.shaded.json.parser.ParseException;

import com.rbc.AuthorizationServer.config.Client_details;
import com.rbc.AuthorizationServer.config.ValidateToken;
import com.rbc.AuthorizationServer.resource.ResourceApi;
import com.rbc.AuthorizationServer.utils.AuthorizationServer;

@RestController
@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })


public class AuthorizationServerApplication {
	

	public static void main(String[] args) throws MalformedURLException, IOException, UnirestException, ParseException  {
		// TODO Auto-generated method stub
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
			if(is_valid_token== true) {
				System.out.println("Token is valid");
				//check if token is expired
				boolean is_token_expire = ValidateToken.check_expiry(token);
				
				if(is_token_expire == false) {
					ResourceApi.get_resource(token);
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

}
