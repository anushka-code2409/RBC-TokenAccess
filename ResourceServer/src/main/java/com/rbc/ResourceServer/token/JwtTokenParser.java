package com.rbc.ResourceServer.token;

import org.springframework.util.Assert;

import com.nimbusds.jose.shaded.json.parser.ParseException;
import com.nimbusds.jwt.JWTParser;

import ch.qos.logback.core.subst.Token;

public class JwtTokenParser {
	
	public Token parse(String token) {
		Assert.notNull(token,"Token must not be null");
		
		try {
			return Token.of(JWTParser.parse(token));
		}
		catch(ParseException e) {
			throw new IllegalArgumentException("Invalid token. It can't be parsed");
		}
	}

}
