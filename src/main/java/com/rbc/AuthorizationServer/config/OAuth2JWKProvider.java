package com.rbc.AuthorizationServer.config;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.NetworkException;
import com.auth0.jwk.SigningKeyNotFoundException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.common.collect.Lists;
import com.rbc.AuthorizationServer.utils.Constants;


/**
 * .SYNOPSIS
 * This class implements JWKProvider interface which is a provider of JWK
 * 
 * .DESCRIPTION
 * This class uses jwkProviderUrl to fetch the JWK and produce jwk representation of it
 * The implementation gets jwkProviderUrl and reads the x5c certificate and validates the signature using x5c certificate
 * 
 * .Method
 * get(), getAll(), getJwks()
 * @author anushkak
 *
 */
public class OAuth2JWKProvider implements JwkProvider {

	//declaration of global variables
	public static URI uri;
	public static String jwkUri;
    
    Logger log = LogManager.getLogger(OAuth2JWKProvider.class);
  

/**
 *.SYNOPSIS
 * This method is used to get the jwk list and compares if the token KeyId is present in jwk keyId
 * 
 * .DESCRIPTION
 * The JwkProvider implements get() method, which gets the KeyId from the decoded token value and compares if found in the jwks List of keyId
 * 
 * @return the found jwk keyId 
 * @throws SigningKeyNotFoundException
 */
    @Override
    public Jwk get(String keyId) throws JwkException {
    	//logging activity
    	log.info("Entering function:" +Thread.currentThread().getStackTrace()[1].getMethodName() );
    	
    	//getting list of jwks  
        final List<Jwk> jwks = getAll();
        if (keyId == null && jwks.size() == 1) {
            return jwks.get(0);
        }
        if (keyId != null) {
        	//iterate inside the jwk list until the keyId equals the jwk keyId
        	log.info("Comparing keyId if found in jwks list..");
            for (Jwk jwk : jwks) {
                if (keyId.equals(jwk.getId())) {
                	
                	//logging activity
                	log.info("Exiting function:" +Thread.currentThread().getStackTrace()[1].getMethodName()+", extracted jwk of found keyId: "+jwk );
                    return jwk;
                }
            }
        }
      //logging activity
    	log.error("Exception occured:" +Thread.currentThread().getStackTrace()[1].getMethodName()+ ", Failed to map keys HashMapList to jwks List" );
        
        throw new SigningKeyNotFoundException("No key found in " + uri.toString() + " with kid " + keyId, null);
    }
    
  
/**
 * .SYNOPSIS
 * This method is used to get the jwk list 
 * .DESCRIPTION
 * This method gets the JWK list with "keys" object from the getJwks() methods which has simple api call to get response from jwkProviderUrl
 * @return list of jwks
 * @throws SigningKeyNotFoundException
 * @throws URISyntaxException 
 */
    public List<Jwk> getAll() throws SigningKeyNotFoundException {
    	//logging activity
    	log.info("Entering function:" +Thread.currentThread().getStackTrace()[1].getMethodName() );
    	List<Jwk> jwks;
    try {
       jwks = Lists.newArrayList();
      //logging activity
    	log.info("Getting keys list from the jwks uri" );
        //store keys List from getJwks()
        final List<Map<String, Object>> keys = (List<Map<String, Object>>) getJwks().get(Constants.KEYS);
        //check if keys value is null
        if (keys == null || keys.isEmpty()) {
            throw new SigningKeyNotFoundException("No keys found in " + uri.toString(), null);
        }

       
        	//creating jwks list  from the keys List HashMap
            for (Map<String, Object> values : keys) {
                jwks.add(Jwk.fromValues(values));
            }
        } catch (IllegalArgumentException | URISyntaxException e) {
        	//logging activity
        	log.error("Exception occured:" +Thread.currentThread().getStackTrace()[1].getMethodName()+ ", Failed to map keys HashMapList to jwks List" );
            throw new SigningKeyNotFoundException("Failed to map keys HashMapList to jwks List", e);
        }
      //logging activity
    	log.info("Exiting function:" +Thread.currentThread().getStackTrace()[1].getMethodName()+", extracted jwks list: "+jwks );

        return jwks;
    }
 /**
  * This method gets value of jwk url from config file  
  * @param jwkUrl
  * @return string value of Jwk url
  */
    public String getJwkUrl(String jwkUrl) {
    	jwkUri = jwkUrl;
  		return jwkUri;
      	
      }

 /**
  * .SYNOPSIS
  * This method maps the response and get the jwk into the map<string,object>
  * 
  * .DESCRIPTION
  * This methods has simple api call to get the Jwks from the JwkProviderurl
  * 
  * @return the response of the api call, i.e returns the Map of keys and respective kid
  * @throws SigningKeyNotFoundException
 * @throws URISyntaxException 
  */
    public Map<String, Object> getJwks() throws SigningKeyNotFoundException, URISyntaxException {
    	//logging activity
    	log.info("Entering function:" +Thread.currentThread().getStackTrace()[1].getMethodName() );
    	URI uri = new URI(jwkUri).normalize();
    	ObjectReader reader = new ObjectMapper().readerFor(Map.class);
    	
        try {
        	
       //making api get call to fetch the keys from uri
        	log.info("attempting to make api call..");
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .headers("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
          //logging activity
        	log.info("Exiting function:" +Thread.currentThread().getStackTrace()[1].getMethodName()+", with response: "+reader.readValue(response.body()) );
            return reader.readValue(response.body());
           

        } catch (IOException | InterruptedException e) {
        	//logging activity
        	log.error("Exception occured:" +Thread.currentThread().getStackTrace()[1].getMethodName()+ ", Cannot obtain jwks from url" );
            throw new NetworkException("Cannot obtain jwks from url " + uri.toString(), e);
        }
    }



}
