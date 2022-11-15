package com.rbc.AuthorizationServer.exception;

public class UnauthorizedException extends RuntimeException {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private int code;

	public UnauthorizedException(int code,String message) {
        super(message);
    }
	public int getCode() {
		return code;
	}
}
