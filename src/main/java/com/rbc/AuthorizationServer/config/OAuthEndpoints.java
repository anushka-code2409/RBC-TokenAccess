package com.rbc.AuthorizationServer.config;

public class OAuthEndpoints {

	private String issuerURL;
	
	
	
	OAuthEndpoints(){
		
	}
	public String getIssuerURL(){
		return issuerURL;			
	}
	
	public void setIssuerURL(String issuerURL){
		this.issuerURL = issuerURL;
	}
	
//	public String getaltIssuerURL(){
//		return altIssuerURL;			
//	}
//	
//	public void setaltIssuerURL(String altIssuerURL){
//		this.altIssuerURL = altIssuerURL;
//	}
}
