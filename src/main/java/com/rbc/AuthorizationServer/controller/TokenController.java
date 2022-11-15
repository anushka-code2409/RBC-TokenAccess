package com.rbc.AuthorizationServer.controller;

import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rbc.AuthorizationServer.token.AuthService;


@RestController
@CrossOrigin(origins ="*" )
public class TokenController {
	
	/**
	 * .SYNOPSIS
	 *  This class is used to store api routes and controller
	 * .Description
	 *  This class consists of PostMapping controller to handle POST type of request method 
	 *  .Methods
	 *  tokenGenerate()
	 *  
	 * @return success message if the token is validated successfully
	 * @throws NetworkException, UnirestException
	 */
	@Autowired
	AuthService authService = new AuthService() ;
	
		Logger log = LogManager.getLogger(TokenController.class);
		Properties clientProperty;
		@GetMapping("/token")
				

		
		public String getAuthCodeUrl(Properties clientProperty) {
			return  authService.getCodeURI(clientProperty);
			 	
		}
		public JSONObject getAuthTokenResponse(Properties clientProperty, boolean isRefreshToken) {	
			
			return authService.getTokenResponse(clientProperty, isRefreshToken);
			 
				
		}
		public JSONObject getSessionTokenResponse(Properties clientProperty) {
			
			return authService.getSessionToken(clientProperty);
		}
		

}
