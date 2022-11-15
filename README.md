# Module: AzureAD library development
The AzureAD client library is a collection of multiple collaboration and security-related libraries built on top of OAuth2.0 and the OpenID Connect protocol. Client applications need the access token/id token issued by the identity providers like Azure AD, Okta, AWS, etc. to access the resource server data.

The product libraries expose the function to make the request to the identity providers to fetch the access token or id token access token and validate the access token response from the provider. Once the token metadata is validated, the token can be used to either to make the call to the resource server api and get the response.

# Client credential grant type
Client credential grants are used for application-to-application communication when both the client and the resource are servers. In the client credentials flow, the Authorization Server provides an access token directly to the client app after verifying the client app’s client ID and client secret. This access token is then passed under the Authorization header as a bearer token to the resource server. The resource server verifies the access token and, once the signature is verified, it responds back to the client with the requested data.

## Steps:
Following steps are carried out as a part of client credential pattern implementation:

1. The Stub app makes the call to get the access_token from the client app via the tokenService function GetAccessToken before making a call to the resource server.
2. Clientapp checks if a valid token already exists.
     1. If a valid token exists, it returns the token back to the stub app, which is then passed to the resource server as a bearer token within the Authorization header.
     2. If a valid token does not exist, then the client app makes a post call to the identity provider with post body parameters like client_id, client_secret, grant_type, resource, etc.
     3. The access_token is returned by the identity server after it successfully validates the request body. 
     4. The metadata of the identity server response is validated for valid resources, expiration, and nbf within the Clientapp.
3. After the access_token is successfully validated, the Clientapp returns access_token to the Stub app.
4. The StubApp then makes the call to the resource server with the access_token passed as the bearer token within the authorization header.


# Authorization Code + PKCE grant type
The Authorization Code Flow + PKCE is an OpenId Connect flow specifically designed to authenticate native or mobile application users. In this pattern, the client app creates a unique string value, code_verifier, which it hashes and encodes as a code_challenge. When the client app initiates the first part of the Authorization Code flow, it sends a hashed code_challenge. Once the identity provider authenticates the request and the authorization code is returned to the client app, it uses the authorization code to make a request to the identity server for an access_token in exchange for the authorization code. The client app must include the original unique string value in the code_verifier parameter. If the codes match, the authentication is complete and an access_token is returned along with other information.

## Steps:
Following steps are carried out as a part of Authorization Code + PKCE pattern implementation:
 1. The stub application calls the client app to fetch the tokens from the auth server.
 2. If a id_token already exists within the client app, the app validates metadata and the id_token for expiration. Once validated successfully, returns the id_token along with access_token back to the stub app.
 3. If a valid token exists but has expired then the client app makes the refresh token call to refresh the expired token. After getting new the token, it validates the metadata and sends it_token, access_token back to the stub app.
 4. If the token does not exists then following steps are triggered as a part of fetching new token:
     1. Generate an authorization code url. Generating an authorization code involves following further steps:
          1. Generate code verifier: A random string used for creating a code challenge.
          2.Generate a code challenge: A string that is generated using the algorithm SH256 and the code verifier.
          3. Generate nonce: The random string that is used to pass under the nonce parameter.
          4. Once all the parameters are available, the final url is created with the base url as the identity server authorization server url and the following query parameters: client_id, response_type, redirect_uri, scope, code_challenge, code_challenge_method, and nonce.
          
     2. The generated authorization code url is used to make the request to the identity provider that prompts to a login page. Once the credentials are passed, the identity server validates the user and redirects back to the redirect url with the code as a query parameter.
     3. The authorization code from step 2 is extracted and used to make the access token request to the identity provider, which should return the set of tokens, namely  id_token, access_token, and refresh_token.
     4. The id_token is decoded for the signature validation and the metadata is validated for token_type, expiration, resource, nbf, and nonce.
     5. After the id_token is successfully validated, id_token, access_token is returned back to the stub app.
     
5. The StubApp then makes the call to the resource server with the access_token passed as the bearer token within the authorization header.

# Client application
We have provided you with three different solutions: ClientApp, Stub Application, and ClientAppTest.

ClientApp: This is the core library which handles: i. The interaction with the authorization server for fetching the access token. b. Validation of the access token. c. Maintainance of the access token

ClientAppTest: This app is the collection of unit classes for the ClientApp.

Stub Application: The stub application is the user interface that has ClientApp as the project dependency. We use this app to test and run our core app, i.e., ClientApp. Once the stub application is up and running, we should be able to see the different links to test/call different patterns. Stub application loads all the required config and calls the ClientApp services.


The following products have been used as a part of development process:

1. Eclipse: As IDE for development.
2. JDK 11: As development environment for java
3. Apache maven: To build java project into output types like JAR,WAR,etc
4. Apache Tomcat server: To run the stubApplication on the server 
5. Azure AD: As an authorization server.
6. Postman: For testing the end-points.
7. Git: As a version controller.

---

## Before you begin

### 1. Prerequisites

The following pre-requisite steps/configurations must be in place before this library can be used: 
1. The user executing the libraries needs to have `read/write` permissions on the folder containing the libraries codebase
2. Client and resource app registration under identity provider like Azure AD
3. The user executing the libraries needs to have necessary secrets like resource, issuer, appId etc.
4. Eclipse Version 2022-06 (4.24.0)
5. JDK Version 11.0.15.1
6. Apache maven version 3.8.6
7. Apache Tomcat server 9.0.65


### 2. Library permissions

The minimum permissions required for library ap have been listed below:
#### 2.1 Roles required to write logs
```
Full folder permission - To write and delete the logs, the app should have the write access to the environment where it is hosted.
```

# Configuration file
## AzureAD library :: Configuration file

***Configurable Values***

The following configurations in the application.properties file can be modified based on the Identity providers:

## Common to Client Credentials and AuthCode PKCE grant type
---
|     Parameter | Mandatory/Optional   |    Description  | Allowed / Existing Values  |
|---------------|----------------------|-----------------|----------------------------|
| auth.audience | Mandatory | It contains the resource values supplied by the azure ad app registration |api://5d7e7fa0-2c7a-42f4-b5b8 | 
| auth.Issuer | Mandatory | It holds the token issuer uri needed to validate the token | https://sts.windows.net/adjfewfwf  |
| auth.grantType | Mandatory | Grant type is required param, required in token post body | client_credentials |           
| auth.tokenUrl | Mandatory | Identity provider token end-point to fetch the access token  | Type, Id, Error, Description | 
| auth.clientId | Mandatory | client id is used with in the request body to fetch the token  | 1995eafd-5cbc-4030-afd0-b094e076ee97 | 
| auth.clientSecret | Mandatory | client secret is used with in the request body to fetch the token | Pxm8Q~Xz6Ph0FIDmNOvzv8IUMN4lUFGnigGsWdid | 
| auth.CredentialType | Mandatory | This is the config value which is used to decide on how get the token, either by client assertion or client secret | certificate/secret | 
| auth.ClientAssertionType | Mandatory | ClientAssertionType is used with in the request body to fetch the token | urn:ietf:params:oauth:client-assertion-type:jwt-bearer | 
| auth.Thumbprint | Mandatory | Thumbprint is used to generate client assertion to generate token | urn:ietf:params:oauth:client-assertion-type:jwt-bearer | 
| auth.PublicKey | Mandatory | publicKEY is used to generate certificate and extract thumbprint from the certificate | MIIDhzCCAm+gAwIBAgIUA6RBnN4351wa6EZQ3MVr |  
| auth.PrivateKey| Mandatory | privateKEY is used to generate client assertion and sign the certificate with private key | MIIDhzCCAm+gAwIBAgIUA6RBnN4351wa6EZQ3MVr | 

## AuthCode PKCE grant type
----------------------------------------------------------------------------------------
|  Parameter | Mandatory/Optional   |  Description   | Allowed/Existing Values  |
|------------|----------------------|----------------|--------------------------|
| auth.RedirectUri | Mandatory | RedirectUri is required to construct an access token url request to the identity server.| http://localhost:8080/StubApplication/ConfidentialClient |
| auth.CodeChallengeUri| Mandatory | It is used by the GetCodeUrl method to generate absoluteUri.| https://login.microsoftonline.com/4de6a784-e874-4f76-bbbe-a3382e04ec29/oauth2/v2.0/authorize |
| auth.CodeChallangeMethodAlg| Mandatory | It is used to hold the algorithm value used for hashing the code-challenge.|S256 |
| auth.Scope| Mandatory | It is used to build the auth-code request body to fetch the access token and refresh token.|"api://5d7e7fa0-2c7a-42f4-b5b8-887e00ae980a/.default openid |
| auth.CodeResponseType | Mandatory | CodeResponseType is used with in the request body to fetch the token | code |  



---------------------------------------------------------------------------------------------------------------------------------------------



# Constant file
## AzureAD library :: Constant file

***Fixed Values***

DO NOT change these configurations in the Constants.java file:

---
| Parameter | Mandatory/Optional   |    Description     | Allowed / Existing Values  | Grant Type |
|-----------|----------------------|--------------------|----------------------------|------------|
| NOT_BEFORE | Mandatory | It is used to store not before metadata of token  | not_before | Client Credential, Auth Code + PKCE |
| EXPIRES_ON | Mandatory | It is used to store expiration metadata of token  | expires_on | Client Credential, Auth Code + PKCE |
| RESOURCE |Mandatory|	It is used to store resource metadata of token | resource | Client Credential, Auth Code + PKCE |
| TOKEN_TYPE |Mandatory| It is used to store token type metadata of token | token_type | Client Credential, Auth Code + PKCE |
| ACCESSTOKEN | Mandatory| It is used to store access token metadata of token | access_token | Client Credential, Auth Code + PKCE|
| RSA | Mandatory| It is used to store rsa value to generate token using client certificate | RSA | Client Credential, Auth Code + PKCE|
| X509 | Mandatory| It is used to store x509 certificate value to generate token using client certificate | X.509 | Client Credential, Auth Code + PKCE|
| SHA1 | Mandatory| It is used to store sha-1 value to generate token using client certificate | SHA-1 | Client Credential, Auth Code + PKCE|
| RS256 | Mandatory| It is used to store Algorithm to sign the certificate with private key | RS256 | Auth Code + PKCE|
| RESPONSE_TYPE | Mandatory| It is used to store response type for token generation | response_type | Auth Code + PKCE|
| CODE_RESPONSE_TYPE | Mandatory| It is used to store code response type of token as code | code | Client	Credential, Auth Code + PKCE|
| REDIRECT_URI | Mandatory| It is used to store redirect uri | redirect_uri | Auth Code + PKCE|
| SCOPE_API | Mandatory| It is used to store scope constant | scope | Client	Credential, Auth Code + PKCE|
| CODE_CHALLENGE | Mandatory| It is used to store code challenge generated for token | code_challenge | Auth Code + PKCE|
| CODE_CHALLENGE_METHOD | Mandatory| It is used to store code challenge method generated for token | code_challenge_method |  Auth Code + PKCE|
| CODE_VERIFIER | Mandatory| It is used to store code verifier generated for token | code_verifier | Auth Code + PKCE|
| JWT | Mandatory| It is used to store code verifier generated for token | JWT | Auth Code + PKCE|
| NONCE | Mandatory| It is used to store nonce to generate token value | nonce | Auth Code + PKCE|
| IDTOKEN | Mandatory| It is used to store id token value generated from token | id_token | Auth Code + PKCE|
| REFRESHTOKEN | Mandatory| It is used to store refresh token value generated from token | refresh_token | Auth Code + PKCE|
| KEYS | Mandatory| It is used to store keys value to validate signature of the id token | keys | Auth Code + PKCE|
    

-------------------------------------------------------------------------------------------------------------------------------------------------


# Log file{Base-Folder/logs}

The log file contains information that are logged from different section/function of the application. The file is used for debugging the issues or to log the app related important informations.

 Note: the naming convention of logs goes like "yyyy-mm-dd.log" so for there should be one file.

 
# Executing Client_Credentials pattern 

Steps for local linking of package:-
1. Add plugin under plugins in pom.xml file
	
	<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
			</plugin>
			<plugin>
      <artifactId>maven-assembly-plugin</artifactId>
      <configuration>
        <archive>
          <manifest>
            <mainClass>com.rbc.AuthorizationServer.AuthorizationServerApplication</mainClass>
          </manifest>
        </archive>
        <descriptorRefs>
          <descriptorRef>jar-with-dependencies</descriptorRef>
        </descriptorRefs>
      </configuration>
    </plugin>
	
2. Build client Application project by giving maven build goals:
		
		 clean compile assembly:single -Dmaven.test.skip=true
	
or run the command
	
	 mvn clean compile assembly:single -Dmaven.test.skip=true 
	
3. Add the JAR file created in project structure \ClientApp\target\AuthorizationServer-1.1.1-SNAPSHOT-jar-with-dependencies.jar of client appln to the classPath of Stub Application.
4. Right click on project structure >>Properties>> Java build path>> Add external JAR and the Jar file created in target folder of client application project structure..
5. Copy and paste the Jar file at /StubApplication/src/main/webapp/WEB-INF/lib
6. Run the class main.jsp by right clicking and Run on server (add installed tomcat server to the server port)
7. The Tomcat server will automatically open the browser and will run on http://localhost:8080/.
8. Click on the client credential link from the header bar.
9. Once the client credential link is clicked, the stub application will fetch the token from the client app library. After getting the token from the client app library, send the token with the header to call the resource api for the data.
10. The resource api validates the token present in the header for the signature and claims. Once the token is validated successfully, the resource api sends the data to the stub application and shown on the UI.


# Executing Authorization Code pattern: 

Steps for local linking of package:-
1. Add plugin under plugins in pom.xml file
	
	<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
			</plugin>
			<plugin>
      <artifactId>maven-assembly-plugin</artifactId>
      <configuration>
        <archive>
          <manifest>
            <mainClass>com.rbc.AuthorizationServer.AuthorizationServerApplication</mainClass>
          </manifest>
        </archive>
        <descriptorRefs>
          <descriptorRef>jar-with-dependencies</descriptorRef>
        </descriptorRefs>
      </configuration>
    </plugin>
	
2. Build client Application project by giving maven build goals:
		
		 clean compile assembly:single -Dmaven.test.skip=true
	
or run the command
	
	 mvn clean compile assembly:single -Dmaven.test.skip=true 
	
3. Add the JAR file created in project structure \ClientApp\target\AuthorizationServer-1.1.1-SNAPSHOT-jar-with-dependencies.jar of client appln to the classPath of Stub Application.
4. Right click on project structure >>Properties>> Java build path>> Add external JAR and the Jar file created in target folder of client application project structure..
5. Copy and paste the Jar file at /StubApplication/src/main/webapp/WEB-INF/lib
6. Run the class main.jsp by right clicking and Run on server (add installed tomcat server to the server port)
7. The Tomcat server will automatically open the browser and will run on http://localhost:8080/.
8. Click on the AuthCode PKCE Confidential Client link from the header bar.
9. Once the AuthCode PKCE Confidential Client link is clicked, it should redirect the user to the identity provider login page.
10. Once the user provides the credentials, the identity provider verifies the user's credentials and issues the user with an authorization code.
11. The authorization code is then used by the client app to issue a token request to the identity provider.
 10. After successfully fetching the token from the identity server, the client app validates the metadata and returns the id_token along with access_token back to the stub app.
12. The StubApp then makes the call to the resource server with the access_token passed as the bearer token within the authorization header.
13. The resource api validates the token present in the header for the signature and claims. Once the token is validated successfully, the resource API sends the data to the client app, which is then transferred to the stub application and shown on the UI.

---