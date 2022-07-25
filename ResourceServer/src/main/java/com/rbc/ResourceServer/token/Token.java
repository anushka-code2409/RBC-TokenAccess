package com.rbc.ResourceServer.token;

import org.springframework.util.Assert;

import com.nimbusds.jwt.JWT;

public class Token {
	
	private final TokenType tokenType;
	private final JWT jwt;
	
	private Token(TokenType tokenType,JWT jwt ) {
		Assert.notNull(tokenType,"tokenType must not be null");
		Assert.notNull(jwt,"jwt must not be null");
		
		this.tokenType = tokenType;
		this.jwt = jwt;
	}
	public static Token of(TokenType tokenType,JWT jwt) {
		return new Token(tokenType,jwt);
	}
	
	public static Token accessTokenOf(JWT jwt) {
		return new Token(TokenType.ACCESS_TOKEN,jwt);
	}

}
