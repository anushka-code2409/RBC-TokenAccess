package com.rbc.AuthorizationServer.config;

import java.util.HashMap;
import java.util.Map;

import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.client.service.impl.StaticClientConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticSingleIssuerService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.Assert;

@Import(value = {Client_details.class, OAuthEndpoints.class, })
public class OAuth2Config {
	public OAuth2Config(){}
	
	@ConditionalOnMissingBean
	@Bean
	
	OIDCAuthenticationProvider openIdConnectAuthenticationProvider(){
		return new OIDCAuthenticationProvider();
	}
	@ConditionalOnMissingBean
	@Bean
	IssuerService issuerService(final OAuthEndpoints oauthEndpoints){
		Assert.notNull(oauthEndpoints,"OAuth2EndPoints must not be null");
		
		StaticSingleIssuerService issuerService = new StaticSingleIssuerService();
		issuerService.setIssuer(oauthEndpoints.getIssuerURL());
		return issuerService;
	}
	
	@ConditionalOnMissingBean
	@Bean
	
	RegisteredClient clientConfiguration(final Client_details clientDetails){
		Assert.notNull(clientDetails, "OAuth2ClientDetails must not be null");
		
		RegisteredClient client = new RegisteredClient();
		client.setClientId(clientDetails.getClientSecret());
		client.setClientSecret(clientDetails.getClientId());
//		client.setTenantId(clientDetails.getTenantId());
		client.setGrantTypes(clientDetails.getgrantType());
////		client.setTokenEndpointAuthMethod(ClientDetailsEntity.AuthMethod.NONE);
//		Set<String> redirectUris = new HashSet<> ();
//		client.setRedirectUris(redirectUris);
		return client;
	}
	
	@ConditionalOnMissingBean
	@Bean
	
	ClientConfigurationService clientConfigService(final OAuthEndpoints oauthEndpoints, final Client_details clientDetails ){
		Assert.notNull(oauthEndpoints, "OAuth2EndPoints must not be null");
		Assert.notNull(clientDetails, "OAuth2ClientDetails must not be null");
		
		StaticClientConfigurationService clientConfig = new StaticClientConfigurationService();
		Map<String, RegisteredClient> clientsMap = new HashMap<>();
		RegisteredClient client = clientConfiguration(clientDetails);
		clientsMap.put(oauthEndpoints.getIssuerURL(),client);
//		clientsMap.put(oauthEndpoints.getaltIssuerURL(),client);
		clientConfig.setClients(clientsMap);
		return clientConfig;
		
			}
	
	@ConditionalOnMissingBean
	@Bean
	
	AuthenticationEntryPoint authenticationEntryPoint(Environment env){
		boolean forceHttps = env.getProperty("config.forceHttps", Boolean.class, false);
		LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint("/oauth2/token");
		entryPoint.setForceHttps(forceHttps);
		return entryPoint;
		
	}

}
