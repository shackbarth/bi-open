/*
 * Copyright 
 *
 */
package com.xtuple.springsecurity.OauthSSO;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.ui.basicauth.BasicProcessingFilter;

/**
 * Used by the <code>SecurityEnforcementFilter</code> to commence
 * authentication via the {@link BasicProcessingFilter}.
 * 
 * <P>
 * Once a user agent is authenticated using Request Parameter authentication, logout
 * requires that the browser be closed or an unauthorized (401) header be
 * sent. The simplest way of achieving the latter is to call the {@link
 * #commence(ServletRequest, ServletResponse)} method below. This will
 * indicate to the browser its credentials are no longer authorized, causing
 * it to prompt the user to login again.
 * </p>
 */
public class UserTokenFilterEntryPoint implements AuthenticationEntryPoint, InitializingBean {
  //~ Instance fields ========================================================

  //~ Methods ================================================================

  public void afterPropertiesSet() throws Exception {
    // Everything is OK
  }

  public void commence(final ServletRequest request, final ServletResponse response, final AuthenticationException authException)
      throws IOException, ServletException {
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
  }
}
