package com.rbc.ResourceServer.token;

import ch.qos.logback.core.subst.Token;

public interface TokenService {
	
	String validate(Token token);

}
