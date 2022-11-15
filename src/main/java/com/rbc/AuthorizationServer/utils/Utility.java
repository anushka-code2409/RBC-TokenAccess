package com.rbc.AuthorizationServer.utils;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import com.rbc.AuthorizationServer.exception.UnauthorizedException;

public class Utility {
	public String encryptString(String token, String secretKeyString){

		Key secretKey = new SecretKeySpec(secretKeyString.getBytes(), 0, secretKeyString.getBytes().length, "AES");
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(token.getBytes("UTF-8")));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | UnsupportedEncodingException e) {
			throw new UnauthorizedException(401,"Failed to encrypt the access token");
		}
	}

	public String getHashString(String stringToHash)  {

		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] byteEncryptedHash = digest.digest(stringToHash.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(byteEncryptedHash);
		} catch (NoSuchAlgorithmException e) {
			throw new UnauthorizedException(401,"Failed to encrypt the access token");
		}

	}

}
