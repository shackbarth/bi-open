
package com.xtuple.springsecurity.OauthSSO;

import static org.springframework.security.jwt.codec.Codecs.concat;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;

import javax.servlet.http.HttpServletRequest;
import javax.security.cert.X509Certificate;
import javax.security.cert.CertificateException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.BadCredentialsException;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.RestTemplate;
//import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.ObjectNode;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.type.TypeReference;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Date;
import java.io.OutputStream;
import java.nio.charset.Charset;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnManagerParams;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.util.EntityUtils;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;

/**
 * Provide authentication returning a UserTokenAuthentication to the filter.
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
public class UserTokenAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    //~ Instance fields ================================================================================================

	private static final Log logger = LogFactory.getLog(UserTokenAuthenticationProvider.class);
	private String userTokenPublicKey;
	private String userAccountPrivateKey;
	private String issClientID;
	private String acceptAllSslCerts;
	
	final byte[] PERIOD = utf8Encode(".");
	final String HEADER_RSA = new String(utf8Encode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"));
	
	private HttpClient httpClient;
	private ClientConnectionManager cm;
	
    //~ Classes ========================================================================================================
	
	static class AlwaysTrustManager implements X509TrustManager {
			public void checkClientTrusted(
					java.security.cert.X509Certificate[] chain, String authType)
					throws java.security.cert.CertificateException {
			}
			public void checkServerTrusted(
					java.security.cert.X509Certificate[] chain, String authType)
					throws java.security.cert.CertificateException {
			}
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		   }
	
    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userTokenPublicKey,
                (" UserTokenAuthenticationProvider.ERROR_userTokenPublicKey_Missing")); //$NON-NLS-1$
        Assert.notNull(this.userAccountPrivateKey,
                (" UserTokenAuthenticationProvider.ERROR_userAccountPrivateKey_Missing")); //$NON-NLS-1$
        Assert.notNull(this.issClientID,
                (" UserTokenAuthenticationProvider.ERROR_issClientID_Missing")); //$NON-NLS-1$
        Assert.notNull(this.acceptAllSslCerts,
                (" UserTokenAuthenticationProvider.ERROR_acceptAllSslCerts")); //$NON-NLS-1$
    }
    
	public void setUp() throws Exception {
	
        // Create and initialize HTTP parameters
        HttpParams params = new BasicHttpParams();
        ConnManagerParams.setMaxTotalConnections(params, 100);
        HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
        
        // Create SocketFactory (one that accepts all certs if necessary)
        SSLContext sslContext = SSLContext.getInstance("SSL");
        SSLSocketFactory sf;
        if (acceptAllSslCerts.equals("true")){
        	sslContext.init(null, new TrustManager[] {new AlwaysTrustManager()}, new SecureRandom()); 
            sf = new SSLSocketFactory(sslContext);
            UserTokenAuthenticationProvider.logger.warn("Security alert - set up AlwaysTrustManager for SSL. See acceptAllSslCerts in applicationContext-spring-security.xml");
        }
        else{
        	sf = SSLSocketFactory.getSocketFactory();
        }
        
        // Create and initialize scheme registry 
        SchemeRegistry schemeRegistry = new SchemeRegistry();
        schemeRegistry.register(
                new Scheme("https", sf, 443));
        
        // Create an HttpClient with the ThreadSafeClientConnManager.
        // This connection manager must be used if more than one thread will
        // be using the HttpClient.
        cm = new ThreadSafeClientConnManager(params, schemeRegistry);
        httpClient = new DefaultHttpClient(cm, params);
        
		}
	 
	public void cleanUp() throws Exception {
		cm.shutdown();
		}
    
	/***************************************************************************
	 * 
	 * Useful if Spring 3.0 can be used.  See other notes
	 *
	public class FormRequestCallback implements RequestCallback {
		
		private String formData;
		
		public FormRequestCallback(String formData){
			this.formData = formData;			
		}
		
		public void doWithRequest(ClientHttpRequest request) throws IOException {
			OutputStream os = request.getBody();
			os.write(formData.getBytes());
		}
	}
	******************************************************************************/

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }
        //
        // Get JWT assertion and decode to get user prn and org
        //
        String assertionUserToken = (String) authentication.getDetails();
        
		Jwt jwtUserToken = JwtHelper.decode(assertionUserToken);
		try {
			// accepts private key (??) but signature doesn't verify
			//jwtUserToken.verifySignature(new RsaVerifier(userTokenPublicKey));
		}
			catch(InvalidSignatureException e) {
				e.printStackTrace(System.out);
				throw new BadCredentialsException("UserTokenAuthenticationProvider.ERROR_InvalidSignatureExcedption_userToken") ;
			}
			catch (RuntimeException e) {
				e.printStackTrace(System.out);
				throw new BadCredentialsException("UserTokenAuthenticationProvider.ERROR_GeneralSecurityException_userToken") ;
			}
		String claimsUserToken = jwtUserToken.getClaims();
		
		if (UserTokenAuthenticationProvider.logger.isDebugEnabled()) {
			UserTokenAuthenticationProvider.logger.debug((
			"UserTokenAuthenticationProvider.CLAIMSET_FROM_NODE " + claimsUserToken)); //$NON-NLS-1$
		}
		
		ObjectMapper mapper = new ObjectMapper();
		Map<String, String> theTokenMap;
		try {
			theTokenMap = mapper.readValue(claimsUserToken, Map.class );
		}
		catch (Exception e) {
			throw new BadCredentialsException("UserTokenAuthenticationProvider.ERROR_extracting_userid_in_claim_userToken") ;
		}
		String userToken = theTokenMap.get("prn");
		String userOrg = theTokenMap.get("org");
		String superUser = theTokenMap.get("superuser");
		String userTenant = theTokenMap.get("tenant");
		
		if (userToken == null) {
			throw new BadCredentialsException("UserTokenAuthenticationProvider.ERROR_userid_missing_in_claim_userToken") ;
		}
		//
		// Create the JWT claim for access token.  We use the superuser as the prn as the 
		// user-account REST requires admin privilege.
		//
		ObjectNode claimSegment = mapper.createObjectNode();
		claimSegment.put("iss", issClientID);
		claimSegment.put("prn", superUser);	
		claimSegment.put("scope", theTokenMap.get("scope"));
		claimSegment.put("aud", theTokenMap.get("aud"));
		
		Date today = new Date();
		Date iatDate = new Date(today.getTime());
		int iatTime = Math.round(iatDate.getTime() / 1000);
		claimSegment.put("exp", iatTime + 1800);
		claimSegment.put("iat", iatTime);		
		
		if (UserTokenAuthenticationProvider.logger.isDebugEnabled()) {
			UserTokenAuthenticationProvider.logger.debug((
			"UserTokenAuthenticationProvider.CLAIMSET_FOR_ACCESS_TOKEN " + claimSegment.toString())); //$NON-NLS-1$
		}
		
    	//
    	// Encode JWT header, claim and signature
    	//
		String theHeader = new String(Codecs.b64UrlEncode(HEADER_RSA));
		String theClaim = new String(Codecs.b64UrlEncode(claimSegment.toString()));
		RsaSigner signer = new RsaSigner(userAccountPrivateKey);
		byte[] crypto = signer.sign(concat(Codecs.b64UrlEncode(HEADER_RSA), PERIOD, Codecs.b64UrlEncode(claimSegment.toString())));
		String theSignature = new String(Codecs.b64UrlEncode(crypto));
		//
		//  Set up body of request
		//
		String body = "grant_type=assertion";
		body = body + "&assertion=" + theHeader + "." + theClaim + "." + theSignature;
		
		//System.out.print("............body of access token request " + body);

		byte[] theTokenB = utf8Encode("");
		/*****************************************************************************
		 * 
		 *  If Spring 3.0 could be used with Pentaho the REST api below could be used
		 *  which is thread safe - and easy.  See the jira request for Spring 3.0 support.
		 *  Instead we use httpcomponents with a threadsafe connection manager
		 * 
		 * 
		ByteArrayHttpMessageConverter converter = new ByteArrayHttpMessageConverter();
		converter.setSupportedMediaTypes(Arrays.asList(new MediaType("*", "*")));
    	List<HttpMessageConverter<?>> list = new ArrayList<HttpMessageConverter<?>>();
    	list.add(converter);
 		
		RestTemplate rest = new RestTemplate();
		theTokenB = rest.execute("https://maxhammer.xtuple.com/oauth/token",
				HttpMethod.POST, 
				new FormRequestCallback(body),
				new HttpMessageConverterExtractor(byte[].class , list)
				);
		******************************************************************************/
		
		HttpPost httpPost = new HttpPost(theTokenMap.get("aud"));
		List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		nvps.add(new BasicNameValuePair("grant_type", "assertion"));
		nvps.add(new BasicNameValuePair("assertion", theHeader + "." + theClaim + "." + theSignature));
		try {
			httpPost.setEntity(new UrlEncodedFormEntity(nvps));
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		
        try {            
            // get connection from pool and execute
        	HttpResponse response = httpClient.execute(httpPost);
            HttpEntity entity = response.getEntity();
            if (entity != null) {
            	// EntityUtils does entity.getContent().close() which release connection to pool
                theTokenB = EntityUtils.toByteArray(entity);
            }
            
        } catch (Exception e) {
            httpPost.abort();
            try {
				throw e;
			} catch (Exception e1) {
				e1.printStackTrace();
			}
        }		
		
		String theTokenS = new String(theTokenB);
		Map<String, Integer> tokenMap;
		try {
			tokenMap = mapper.readValue(theTokenS, Map.class );
		}
		catch (Exception e) {
			throw new BadCredentialsException("UserTokenAuthenticationProvider.ERROR_extracting_access_token_userToken") ;
		}
		
		Object theTokenO = tokenMap.get("access_token");
		String accessT = theTokenO.toString();
		
		if (UserTokenAuthenticationProvider.logger.isDebugEnabled()) {
			UserTokenAuthenticationProvider.logger.debug((
			"UserTokenAuthenticationProvider.TOKEN_FROM_NODE " + accessT)); //$NON-NLS-1$
		}
		
		if (accessT == null) {
			throw new BadCredentialsException("UserTokenAuthenticationProvider.ERROR_access_token_missing_userToken") ;
		}
		
		/*****************************************************************************
		 * 
		 *  If Spring 3.0 could be used with Pentaho the REST api below could be used
		 *  which is thread safe - and easy.  See the jira request for Spring 3.0 support.
		 *  Instead we use httpcomponents with a threadsafe connection manager
		 *		
		theTokenB = rest.execute(
				"https://maxhammer.xtuple.com/api/userinfo?access_token=" + accessT,
				HttpMethod.GET, 
				null,
				new HttpMessageConverterExtractor(byte[].class , list)
				);
		*****************************************************************************/
		
		String restURL = theTokenMap.get("datasource") + userOrg + "/api/v1alpha1/resources/user-account/" + userToken + "?access_token=" + accessT;
		
		if (UserTokenAuthenticationProvider.logger.isDebugEnabled()) {
			UserTokenAuthenticationProvider.logger.debug((
			"UserTokenAuthenticationProvider.GET_USERINFO_REST " + restURL)); //$NON-NLS-1$
		}

		HttpGet httpGet = new HttpGet(restURL);
        try {            
            // get connection from pool and execute
        	HttpResponse response = httpClient.execute(httpGet);
            HttpEntity entity = response.getEntity();
            if (entity != null) {
            	// EntityUtils does entity.getContent().close() which release connection to pool
                theTokenB = EntityUtils.toByteArray(entity);
            }
            
        } catch (Exception e) {
            httpPost.abort();
            try {
				e.printStackTrace();
				throw e;
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
        }		
		
		theTokenS = new String(theTokenB);

		//
		// Construct authorities based on privileges.  Everyone is Authenticated (all Pentaho users must
		// have this privilege.   If they have ViewSalesHistory xTuple privilege, they get Sales Pentaho
		// privilege.
		// 
		
    	List listAuth = new ArrayList<GrantedAuthority>();
    	listAuth.add(new GrantedAuthorityImpl("Authenticated"));
		
		Object dataNode;
		Map<String, Integer> objMap;
		try {
			objMap = mapper.readValue(theTokenS, Map.class );
			dataNode = objMap.get("data");
		}
		catch (Exception e) {
			throw new BadCredentialsException("UserTokenAuthenticationProvider.ERROR_extracting_user_privileges") ;
		}
		if (dataNode.toString().contains("ViewSalesHistory")) {
		    	listAuth.add(new GrantedAuthorityImpl("Sales"));
		    	listAuth.add(new GrantedAuthorityImpl("CRM"));
			}
		if (dataNode.toString().contains("ViewAccountingDesktop")) {
	    	listAuth.add(new GrantedAuthorityImpl("Financial"));
		}	

		//
    	// Create authenticated user - don't use setAuthenticated().  Silly interface doesn't support
    	// setGrantedAuthority so create a new one.
    	//
    	UserTokenAuthentication authResult = 
    				new UserTokenAuthentication(userToken + "-" + userTenant + "." + userOrg, 
    														userToken + "-" + userTenant + "." + userOrg + "-password", 
    														(GrantedAuthority[]) listAuth.toArray(new GrantedAuthority[listAuth.size()]));
        return authResult;
    }

    public boolean supports(Class authentication) {
        return (UserTokenAuthentication.class.isAssignableFrom(authentication));
    }
    
    public String getuserTokenPublicKey() {
        return userTokenPublicKey;
    }

    public void setuserTokenPublicKey(String userTokenPublicKey) {
        this.userTokenPublicKey = userTokenPublicKey;
    }
    
    public String getuserAccountPrivateKey() {
        return userAccountPrivateKey;
    }

    public void setuserAccountPrivateKey(String userAccountPrivateKey) {
        this.userAccountPrivateKey = userAccountPrivateKey;
    }
    
    public String getissClientID() {
        return issClientID;
    }

    public void setissClientID(String issClientID) {
        this.issClientID = issClientID;
    }
    
    public String getacceptAllSslCerts() {
        return acceptAllSslCerts;
    }

    public void setacceptAllSslCerts(String acceptAllSslCerts) {
        this.acceptAllSslCerts = acceptAllSslCerts;
    }
}

