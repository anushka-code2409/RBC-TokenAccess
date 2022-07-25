package com.rbc.ResourceServer.token;

import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.core.subst.Token;

public class DefaultTokenService implements TokenService {

	private final ClientConfigurationService clientConfigurationService;
	private final OAuth2Endpoints oauthEndpoints;
	private final OIDCAuthenticationFilter authFilter;
	private final ServerConfigurationService serverConfigurationService;
	
	private static final int timeSkewAllowance = 300;
	
	private final JWKSetCacheService serverConfigurationService;
	
	private final static org.slf4j.Logger log = LoggerFactory.getLogger(DefaultTokenService.class);
	
	public DefaultTokenService(ClientConfigurationService clientConfigurationService,OAuth2Endpoints oauthEndpoints,OIDCAuthenticationFilter authFilter,ServerConfigurationService serverConfigurationService) {
		Assert.notNull(clientConfigurationService,"clientConfigurationService must not be null");
		Assert.notNull(oauthEndpoints," OAuth2Endpoints must not be null");
		Assert.notNull(authFilter,"OIDCAuthenticationFilter must not be null");
		Assert.notNull(serverConfigurationService,"serverConfigurationService must not be null");
		
	}
	
		
	@Override
	public String validate(Token token) {
		// TODO Auto-generated method stub
		
		if(!token.isSignedJwt()) {
			throw new IllegalStateException("Token is not signed");
		}
		
		
		return null;
	}
	

}
