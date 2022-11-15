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
@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })

public class AuthorizationServerApplication {
	
	public static void main(String[] args)   {
		SpringApplication.run(AuthorizationServerApplication.class, args);
		
		}
	

}
