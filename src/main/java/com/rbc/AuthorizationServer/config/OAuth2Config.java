package com.rbc.AuthorizationServer.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * This class is a configuration class to configure the values from
 * application.properties file .Methods We have getter(), setter()
 * 
 * @author anushkak
 *
 */
@Configuration
@ConfigurationProperties("auth")
public class OAuth2Config {

	public String getRetryDelayTime() {
		return retryDelayTime;
	}

	public void setRetryDelayTime(String retryDelayTime) {
		this.retryDelayTime = retryDelayTime;
	}

	public String getRetryCount() {
		return retryCount;
	}

	public void setRetryCount(String retryCount) {
		this.retryCount = retryCount;
	}

	public String getRetryExceptions() {
		return retryExceptions;
	}

	public void setRetryExceptions(String retryExceptions) {
		this.retryExceptions = retryExceptions;
	}

	@Override
	public String toString() {
		return "OAuth2Config [clientId=" + clientId + ", clientSecret=" + clientSecret + ", tenantId=" + tenantId
				+ ", grantType=" + grantType + ", tokenUrl=" + tokenUrl + ", tokenType=" + tokenType + ", audience="
				+ audience + ", Scope=" + Scope + ", CodeChallangeMethodAlg=" + CodeChallangeMethodAlg
				+ ", RedirectUri=" + RedirectUri + ", CodeChallengeUri=" + CodeChallengeUri + ", CodeResponseType="
				+ CodeResponseType + ", ClientAssertionType=" + ClientAssertionType + ", CredentialType="
				+ CredentialType + ", Issuer=" + Issuer + ", Thumbprint=" + Thumbprint + ", PublicKey=" + PublicKey
				+ ", PrivateKey=" + PrivateKey + ", code=" + code + ", jwksUri=" + jwksUri + ", fingerprint="
				+ fingerprint + ", sessionId=" + sessionId + ", EncryptionKey=" + EncryptionKey + ", ipAddress="
				+ ipAddress + ", state=" + state + ", retryDelayTime=" + retryDelayTime + ", retryCount=" + retryCount
				+ ", retryExceptions=" + retryExceptions + "]";
	}

	public String getPublicKey() {
		return PublicKey;
	}

	public void setPublicKey(String publicKey) {
		PublicKey = publicKey;
	}

	public String getPrivateKey() {
		return PrivateKey;
	}

	public void setPrivateKey(String privateKey) {
		PrivateKey = privateKey;
	}

	private String clientId;
	private String clientSecret;
	private String tenantId;
	private String grantType;
	private String tokenUrl;
	private String tokenType;
	private String audience;
	private String Scope;
	private String CodeChallangeMethodAlg;
	private String RedirectUri;
	private String CodeChallengeUri;
	private String CodeResponseType;
	private String ClientAssertionType;
	private String CredentialType;
	private String Issuer;
	private String Thumbprint;
	private String PublicKey;
	private String PrivateKey;
	private String code;
	private String jwksUri;
	private String fingerprint;
	private String sessionId;
	private String EncryptionKey;
	private String ipAddress;
	private String state;
	private String retryDelayTime;
	private String retryCount;
	private String retryExceptions;
	

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public String getEncryptionKey() {
		return EncryptionKey;
	}

	public void setEncryptionKey(String encryptionKey) {
		EncryptionKey = encryptionKey;
	}

	public String getFingerprint() {
		return fingerprint;
	}

	public void setFingerprint(String fingerprint) {
		this.fingerprint = fingerprint;
	}

	public String getSessionId() {
		return sessionId;
	}

	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}

	public String getJwksUri() {
		return jwksUri;
	}

	public void setJwksUri(String jwksUri) {
		this.jwksUri = jwksUri;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getIssuer() {
		return Issuer;
	}

	public void setIssuer(String issuer) {
		Issuer = issuer;
	}

	public String getThumbprint() {
		return Thumbprint;
	}

	public void setThumbprint(String thumbprint) {
		Thumbprint = thumbprint;
	}

	public String getCredentialType() {
		return CredentialType;
	}

	public void setCredentialType(String credentialType) {
		CredentialType = credentialType;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getTenantId() {
		return tenantId;
	}

	public void setTenantId(String tenantId) {
		this.tenantId = tenantId;
	}

	public String getGrantType() {
		return grantType;
	}

	public void setGrantType(String grantType) {
		this.grantType = grantType;
	}

	public String getTokenUrl() {
		return tokenUrl;
	}

	public void setTokenUrl(String tokenUrl) {
		this.tokenUrl = tokenUrl;
	}

	public String getTokenType() {
		return tokenType;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	public String getAudience() {
		return audience;
	}

	public void setAudience(String audience) {
		this.audience = audience;
	}

	public String getScope() {
		return Scope;
	}

	public void setScope(String scope) {
		Scope = scope;
	}

	public String getCodeChallangeMethodAlg() {
		return CodeChallangeMethodAlg;
	}

	public void setCodeChallangeMethodAlg(String codeChallangeMethodAlg) {
		CodeChallangeMethodAlg = codeChallangeMethodAlg;
	}

	public String getRedirectUri() {
		return RedirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		RedirectUri = redirectUri;
	}

	public String getCodeChallengeUri() {
		return CodeChallengeUri;
	}

	public void setCodeChallengeUri(String codeChallengeUri) {
		CodeChallengeUri = codeChallengeUri;
	}

	public String getCodeResponseType() {
		return CodeResponseType;
	}

	public void setCodeResponseType(String codeResponseType) {
		CodeResponseType = codeResponseType;
	}

	public String getClientAssertionType() {
		return ClientAssertionType;
	}

	public void setClientAssertionType(String clientAssertionType) {
		ClientAssertionType = clientAssertionType;
	}

}
