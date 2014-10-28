/*
 * Copyright 
 *
 */
package com.xtuple.springsecurity.OauthSSO;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.GrantedAuthority;

/**
 * We need our own Token type so our provider can filter out other
 * types of Tokens
 */
public class UserTokenAuthentication extends UsernamePasswordAuthenticationToken {
	
    public UserTokenAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }
    
    public UserTokenAuthentication(Object principal, Object credentials, GrantedAuthority[] authorities) {
    	super(principal, credentials, authorities);
    }    
}
