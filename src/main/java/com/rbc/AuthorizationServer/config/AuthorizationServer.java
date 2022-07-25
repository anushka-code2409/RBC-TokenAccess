package com.rbc.AuthorizationServer.config;

import java.io.InputStream;
import java.util.Map;

import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;


public class AuthorizationServer   {
	
	String tenantId = "4de6a784-e874-4f76-bbbe-a3382e04ec29";
    String clientId = "1995eafd-5cbc-4030-afd0-b094e076ee97";
    String clientSecret = "Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid";
	String resource = "api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a";
	String tokenType = "Bearer";
	

	public static String getAccessToken() throws  UnirestException {

		
		com.mashape.unirest.http.HttpResponse<JsonNode> response = Unirest.post("https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/token")
				  .header("content-type", "application/x-www-form-urlencoded")
				  .body("grant_type=client_credentials&client_id=1995eafd-5cbc-4030-afd0-b094e076ee97&client_secret=Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid"
				  		+ "&resource=api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a")
				  .asJson();
		String token =  response.getBody().toString();
		return token;
	}

}
