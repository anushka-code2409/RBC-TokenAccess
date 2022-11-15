package com.rbc.AuthorizationServer.config;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import com.rbc.AuthorizationServer.utils.Constants;

/**
 * .SYNOPSIS This class is used to set the SSL certificate verfication and set
 * proxy for any http calls .DESCRIPTION This class gets the SSL certificate
 * imported to trust and set the proxy .Methods getHttpClient()
 * 
 * @author anushka
 *
 */
public class SetProxyAndSSL {

	public CloseableHttpClient getHttpClient() {

		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {

			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {

			}
		} };
		CloseableHttpClient httpclient = null;

		try {
			SSLContext sslcontext = SSLContext.getInstance(Constants.SSL);
			sslcontext.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sslcontext.getSocketFactory());
			SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
			// set proxy for rbc.com
			httpclient = HttpClients.custom().setSSLSocketFactory(sslsf)
					.setProxy(new HttpHost(Constants.RBC_PROXY, Constants.RBC_PROXY_PORT_Number)).build();

		} catch (NoSuchAlgorithmException | KeyManagementException e) {

			e.printStackTrace();
		}

		return httpclient;

	}

}
