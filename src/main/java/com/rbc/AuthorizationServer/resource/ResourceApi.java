package com.rbc.AuthorizationServer.resource;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import com.nimbusds.jose.shaded.json.JSONObject;

import java.net.URI;

/**
 * .SYNOPSIS
 * This class is used to get the resource api
 * .Description
 * This class has methods get_resource, where access token is passed through headers as bearer token and the resource api is invoked 
 * @author anushkak
 *
 */

public class ResourceApi {

/**
 * Method to call resource api and pass the access token value
 * @param token
 * @return response for the HTTP post method to invoke resource api
 */
public static String get_resource(JSONObject token) {
	// TODO Auto-generated method stub
	HttpHeaders headers = new HttpHeaders();
	headers.add("Authorization", "Bearer " + token.get("access_token"));
    HttpEntity request = new HttpEntity(headers);
    String url = "http://localhost:9000/test";
    
	// Make the actual HTTP POST request to pass the token value using restTemplate
	RestTemplate restTemplate = new RestTemplate();

	ResponseEntity<String> response = restTemplate.exchange(
			url,
			HttpMethod.POST,
			request,
			String.class
	);
	
	String result = response.getBody();
	System.out.print(result);
	return result;
	
	
	
	}
}
