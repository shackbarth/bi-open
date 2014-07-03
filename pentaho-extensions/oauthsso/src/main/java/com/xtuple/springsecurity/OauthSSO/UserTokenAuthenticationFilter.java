
package com.xtuple.springsecurity.OauthSSO;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
//import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.ui.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;

import org.pentaho.platform.api.engine.ICacheManager;
import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.engine.core.system.PentahoSystem;

/**
 * Processes Request Parameter authorization, putting the result
 * into the <code>SecurityContextHolder</code>.
 * 
 * <p>
 * In summary, this filter looks for request parameter assertion for the JWT token
 * the defines the user
 * </p>
 * 
 * <P>
 * If authentication is successful, the resulting {@link Authentication} object
 * will be placed into the <code>SecurityContextHolder</code>.
 * </p>
 * 
 * <p>
 * If authentication fails and <code>ignoreFailure</code> is <code>false</code>
 * (the default), an {@link AuthenticationEntryPoint} implementation is
 * called. Usually this should be {@link UserTokenFilterEntryPoint}.
 * </p>
 * 
 * <p>
 * <b>Do not use this class directly.</b> Instead configure
 * <code>web.xml</code> to use the {@link
 * org.springframework.security.util.FilterToBeanProxy}.
 * </p>
 * 
 * <p>
 * Having trouble?  Turn on DEBUG logging by setting:
 * 
 *    <category name="com.xtuple">
 *      <priority value="DEBUG" />
 *    </category>
 *    
 * in log4js.xml in pentaho/WEB-INF/classes.  Log is in tomcat/logs/pentaho.log
 * </p>
 * 
 * @author Jeff Gunderson
 *
 */
public class UserTokenAuthenticationFilter implements Filter, InitializingBean {
  //~ Static fields/initializers =============================================

  private static final Log logger = LogFactory.getLog(UserTokenAuthenticationFilter.class);

  //~ Instance fields ========================================================

  private AuthenticationEntryPoint authenticationEntryPoint;
  private AuthenticationManager authenticationManager;
  private boolean ignoreFailure = false;
  private String userTokenParameter;

  //~ Methods ================================================================

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.authenticationManager,
        ("UserTokenAuthenticationFilter.ERROR_0001_authenticationManager_Missing")); //$NON-NLS-1$
    Assert.notNull(this.authenticationEntryPoint,
        ("UserTokenAuthenticationFilter.ERROR_0002_authenticationEntryPoint_Missing")); //$NON-NLS-1$
    Assert.hasText(this.userTokenParameter,
        ("UserTokenAuthenticationFilter.ERROR_0003_UserTokenParamter_Missing")); //$NON-NLS-1$
  }

  public void destroy() {
  }

  public void doFilter(final ServletRequest request, final ServletResponse response, 
		  final FilterChain chain) throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest)) {
      throw new ServletException(("UserTokenAuthenticationFilter.ERROR_0005_HTTP_SERVLET_REQUEST_REQUIRED")); //$NON-NLS-1$
    }
    if (!(response instanceof HttpServletResponse)) {
      throw new ServletException(("UserTokenAuthenticationFilter.ERROR_0006_HTTP_SERVLET_RESPONSE_REQUIRED")); //$NON-NLS-1$
    }
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String userToken = httpRequest.getParameter(this.userTokenParameter);

    /*************************************************
     * We only filter URL's with a userToken parameter
     ************************************************/
    if (userToken != null) {
    	
    	Jwt jwtUserToken = JwtHelper.decode(userToken);
    	String claimsUserToken = jwtUserToken.getClaims();
    	ObjectMapper mapper = new ObjectMapper();
    	Map<String, String> theTokenMap;
    	try {
    		theTokenMap = mapper.readValue(claimsUserToken, Map.class );
    	}
    	catch (Exception e) {
    		throw new BadCredentialsException("UserTokenAuthenticationProvider.ERROR_extracting_userid_in_claim_userToken") ;
    	}
    	String userPrn = theTokenMap.get("prn");
    	String userOrg = theTokenMap.get("org");
    	String userTenant = theTokenMap.get("tenant");	
    	String userPentahoPrn = userPrn + "-" + userTenant + "." + userOrg;
    	String userURL = request.getRemoteAddr();
	
    	/***************************************************************************** 
    	*  Check if the authentication is in our cache.  We cache authentications as
    	*  XMLA does not implement sessions and the Spring SecurityContext can not be
    	*  used to determine if a user is authenticated.
    	*****************************************************************************/
    	HttpSession httpSession = httpRequest.getSession();
    	IPentahoSession pentahoSession = (IPentahoSession) httpSession.getAttribute("pentaho-session-context");
    	ICacheManager cacheMgr = PentahoSystem.getCacheManager(pentahoSession);
    	if(!cacheMgr.cacheEnabled("xtuple-oauthsso-cache")) {
    		cacheMgr.addCacheRegion("xtuple-oauthsso-cache");
    	}
    	Authentication existingAuth = (Authentication)cacheMgr.getFromRegionCache("xtuple-oauthsso-cache", userURL + userPentahoPrn);
    	if(!(existingAuth == null)) {
			if (UserTokenAuthenticationFilter.logger.isDebugEnabled()) {
				UserTokenAuthenticationFilter.logger.debug((
				"UserTokenAuthenticationFilter.AUTHENTICATION_FROM_CACHE " + userURL + userPentahoPrn)); //$NON-NLS-1$
			}
    		SecurityContextHolder.getContext().setAuthentication(existingAuth);
    	}
    	else {
    		/***************************************************************************************************
    		* Only re-authenticate if userToken doesn't match SecurityContextHolder and user isn't authenticated
    		* (see SEC-53).  
    		***************************************************************************************************/    	
    		existingAuth = SecurityContextHolder.getContext().getAuthentication();
    		if ((existingAuth == null) || !existingAuth.getPrincipal().equals(userPentahoPrn) || !existingAuth.isAuthenticated()) {
    			UserTokenAuthentication authRequest = new UserTokenAuthentication(userPentahoPrn, userPentahoPrn + "-password");
    			// Save the request for the authenticationProvider
    			authRequest.setDetails(userToken);
    			Authentication authResult;
    			try {
    				authResult = authenticationManager.authenticate(authRequest);
    			} catch (AuthenticationException failed) {
    				// Authentication failed
    				if (UserTokenAuthenticationFilter.logger.isDebugEnabled()) {
    					UserTokenAuthenticationFilter.logger.debug((
						"UserTokenAuthenticationFilter.FAILED_AUTHENTICATION " + userPentahoPrn)); //$NON-NLS-1$
    				}
    				SecurityContextHolder.getContext().setAuthentication(null);
    				if (ignoreFailure) {
    					chain.doFilter(request, response);
    				} else {
    					authenticationEntryPoint.commence(request, response, failed);
    				}
    				return;
    			}
    			// Authentication success
    			if (UserTokenAuthenticationFilter.logger.isDebugEnabled()) {
    				UserTokenAuthenticationFilter.logger.debug((
    						"UserTokenAuthenticationFilter.SUCCESS_AUTHENTICATION " + userPentahoPrn)); //$NON-NLS-1$
    			}
    			// Set authentication and add to the cache
    			SecurityContextHolder.getContext().setAuthentication(authResult);
    			cacheMgr.removeFromRegionCache("xtuple-oauthsso-cache", userURL + userPentahoPrn);
    			cacheMgr.putInRegionCache("xtuple-oauthsso-cache", userURL + userPentahoPrn, authResult);
    		}
    	}
    }
	chain.doFilter(request, response);
  }

  public AuthenticationEntryPoint getAuthenticationEntryPoint() {
    return authenticationEntryPoint;
  }

  public AuthenticationManager getAuthenticationManager() {
    return authenticationManager;
  }

  public void init(final FilterConfig arg0) throws ServletException {
  }

  public boolean isIgnoreFailure() {
    return ignoreFailure;
  }

  public void setAuthenticationEntryPoint(final AuthenticationEntryPoint authenticationEntryPoint) {
    this.authenticationEntryPoint = authenticationEntryPoint;
  }

  public void setAuthenticationManager(final AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  public void setIgnoreFailure(final boolean ignoreFailure) {
    this.ignoreFailure = ignoreFailure;
  }

  public String getuserTokenParameter() {
    return userTokenParameter;
  }

  public void setuserTokenParameter(final String value) {
    userTokenParameter = value;
  }

}
