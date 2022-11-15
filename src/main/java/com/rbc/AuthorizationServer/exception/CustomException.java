package com.rbc.AuthorizationServer.exception;

public class CustomException extends RuntimeException {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private int code;

	public CustomException(int code,String message) { 
		super(message); }
	public int getCode() {
		return code;
	}

}
