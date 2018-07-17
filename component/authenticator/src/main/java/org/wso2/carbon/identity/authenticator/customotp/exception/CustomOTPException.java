package org.wso2.carbon.identity.authenticator.customotp.exception;

public class CustomOTPException extends Exception {

    public CustomOTPException(String msg) {
        super(msg);
    }

    public CustomOTPException(String msg, Throwable cause) {
        super(msg, cause);
    }
}