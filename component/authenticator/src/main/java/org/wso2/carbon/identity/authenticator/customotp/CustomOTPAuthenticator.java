package org.wso2.carbon.identity.authenticator.customotp;

import org.apache.catalina.util.URLEncoder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.customotp.exception.CustomOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Authenticator of Custom OTP
 */
public class CustomOTPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(CustomOTPAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside CustomOTPAuthenticator canHandle method and check the existence otp code");
        }
        return (StringUtils.isNotEmpty(request.getParameter(CustomOTPConstants.CODE)));
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                            HttpServletResponse response,
                                            AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isEmpty(request.getParameter(CustomOTPConstants.CODE))) {
            // if the request comes with code, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(CustomOTPConstants.AUTHENTICATION)
                    .equals(CustomOTPConstants.AUTHENTICATOR_NAME)) {
                // if the request comes with authentication is CustomOTP, it will go through this flow.
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // if the request comes with authentication is basic, complete the flow.
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            return super.process(request, response, context);
        }
    }

    /**
     * Initiate the authentication request.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                    AuthenticationContext context) throws AuthenticationFailedException {
        
        log.trace("inside initiateAuthenticationRequest() method");                                                
        try {
            String username;
            AuthenticatedUser authenticatedUser;
            context.setProperty(CustomOTPConstants.AUTHENTICATION, CustomOTPConstants.AUTHENTICATOR_NAME);            

            FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty(CustomOTPConstants.USER_NAME));
            authenticatedUser = (AuthenticatedUser) context.getProperty(CustomOTPConstants.AUTHENTICATED_USER);
            // find the authenticated user, throw exception if not found from previous step
            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failed: Could not find the authenticated user. ");
                }
                throw new AuthenticationFailedException
                        ("Authentication failed: Cannot proceed further without identifying the user. ");
            }

            // try to get query params
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String errorPage = getErrorPage(context);

            processCustomOTPFlow(context, request, response, username, queryParams, errorPage);
            
        } catch (CustomOTPException e) {
            throw new AuthenticationFailedException("Failed to initiate authentication request. ", e);
        }
    }

    /*
     * Get the loginPage from authentication.xml file or use the login page from constant file.
     */
    private String getLoginPage(AuthenticationContext context) throws AuthenticationFailedException {

        String loginPage = CustomOTPUtils.getLoginPageFromXMLFile(context);
        if (StringUtils.isEmpty(loginPage)) {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(CustomOTPConstants.LOGIN_PAGE, CustomOTPConstants.CUSTOM_LOGIN_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used");
            }
        }
        return loginPage;
    }

    /*
     * Get the errorPage from authentication.xml file or use the error page from constant file.
     */
    private String getErrorPage(AuthenticationContext context) throws AuthenticationFailedException {

        String errorPage = CustomOTPUtils.getErrorPageFromXMLFile(context);
        if (StringUtils.isEmpty(errorPage)) {
            errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(CustomOTPConstants.LOGIN_PAGE, CustomOTPConstants.ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used");
            }
        }
        return errorPage;
    }

    /*
     * To get the redirection URL. 
     */
    private String getURL(String baseURI, String queryParams) {

        String url;
        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + CustomOTPConstants.NAME_OF_AUTHENTICATORS + getName();
        } else {
            url = baseURI + "?" + CustomOTPConstants.NAME_OF_AUTHENTICATORS + getName();
        }
        return url;
    }

    /*
     * Redirect to an error page.    
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context, String queryParams, String retryParam)
            throws AuthenticationFailedException {        
        try {
            String errorPage = getErrorPage(context);
            String url = getURL(errorPage, queryParams);
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception occurred while redirecting to errorPage. ", e);
        }
    }

    /*
     * Pre-Check with CustomOTP flow
     */
    private void processCustomOTPFlow(AuthenticationContext context, HttpServletRequest request,
                                    HttpServletResponse response, String username,
                                    String queryParams, String errorPage)
            throws AuthenticationFailedException, CustomOTPException {
        proceedWithOTP(response, context, errorPage, queryParams, username);
        
    }

    /*
     * Proceed with One Time Password, call API to submit to generate OTP for this user
     */
    private void proceedWithOTP(HttpServletResponse response, AuthenticationContext context, String errorPage,
                                String queryParams, String username)
            throws AuthenticationFailedException {
        
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();        
            String loginPage = getLoginPage(context);            
            
            try {
                // Call API here and store token to AuthenticationContext
                String otpToken = "123456789";
                context.setProperty(CustomOTPConstants.OTP_TOKEN, otpToken);
                if (log.isDebugEnabled()) {
                    log.debug("Generated OTP successfully and set to the context.");
                }                
                // end
                String url = getURL(loginPage, queryParams);
                response.sendRedirect(url);
            
            } catch (IOException e) {
                throw new AuthenticationFailedException("Error while sending the HTTP request. ", e);
            }
    }

    /*
     * Process the response of the SMSOTP end-point.    
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                    AuthenticationContext context) throws AuthenticationFailedException {

        String userToken = request.getParameter(CustomOTPConstants.CODE);
        String contextToken = (String) context.getProperty(CustomOTPConstants.OTP_TOKEN);
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(CustomOTPConstants.AUTHENTICATED_USER);
        if (StringUtils.isEmpty(request.getParameter(CustomOTPConstants.CODE))) {
            throw new InvalidCredentialsException("Code cannot not be null");
        }
        
        if (userToken.equals(contextToken)) {
            context.setSubject(authenticatedUser);    
        } else {
            context.setProperty(CustomOTPConstants.CODE_MISMATCH, true);
            throw new AuthenticationFailedException("Code mismatch");
        }
    }

    /**
     * Get the friendly name of the Authenticator
     */
    public String getFriendlyName() {

        return CustomOTPConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    public String getName() {

        return CustomOTPConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property httpMethod = new Property();
        httpMethod.setName(CustomOTPConstants.HTTP_METHOD);
        httpMethod.setDisplayName("HTTP Method");
        httpMethod.setRequired(true);
        httpMethod.setDescription("Enter the HTTP Method used by the Custom OTP API");
        httpMethod.setDisplayOrder(1);
        configProperties.add(httpMethod);

        return configProperties;
    }    
}