package org.wso2.carbon.identity.authenticator.customotp;

public class CustomOTPConstants {

    public static final String AUTHENTICATOR_NAME = "CustomOTP";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Custom OTP";    
    public static final String CHAR_SET = "UTF-8";
    public static final String CODE = "OTPcode";

    public static final String HTTP_METHOD = "http_method";    
    public static final String HTTP_RESPONSE = "http_response";

    public static final String GET_METHOD = "GET";
    public static final String POST_METHOD = "POST";

    public static final String CUSTOMOTP_AUTHENTICATION_ENDPOINT_URL = "CUSTOMOTPAuthenticationEndpointURL";
    public static final String CUSTOMOTP_AUTHENTICATION_ERROR_PAGE_URL = "CUSTOMOTPAuthenticationEndpointErrorPage";

    public static final String LOGIN_PAGE = "authenticationendpoint/login.do";
    public static final String CUSTOM_LOGIN_PAGE = "customotpauthenticationendpoint/customotp.jsp";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String ERROR_PAGE = "customotpauthenticationendpoint/customotpError.jsp";
    
    public static final String NAME_OF_AUTHENTICATORS = "authenticators=";
    public static final String OTP_TOKEN = "otpToken";
    public static final String AUTHENTICATION = "authentication";    
    public static final String SUPER_TENANT = "carbon.super";
    public static final String FEDERETOR = "federator";
    public static final String USER_NAME = "username";
    public static final String AUTHENTICATED_USER = "authenticatedUser";    
    public static final String ERROR_MESSAGE = "&authFailure=true&authFailureMsg=";    
    public static final String ERROR_CUSTOMOTP_DISABLE = "&authFailure=true&authFailureMsg=smsotp.disable";
    public static final String ERROR_CUSTOMOTP_DISABLE_MSG = "smsotp.disable";    
    public static final String ERROR_CODE_MISMATCH = "code.mismatch";
    public static final String ERROR_CODE = "errorCode";
    public static final String SCREEN_VALUE = "&screenvalue=";
    public static final String CODE_MISMATCH = "codeMismatch";
}