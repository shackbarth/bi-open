
package com.xtuple.dynschema;

import mondrian.olap.MondrianProperties;
//import mondrian.olap.Parser;
import mondrian.olap.Util;
//import mondrian.rolap.DOMWrapper;
import mondrian.spi.DynamicSchemaProcessor;
import mondrian.spi.impl.FilterDynamicSchemaProcessor;

import org.apache.log4j.Logger;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;

import java.io.InputStream;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.context.SecurityContextHolder;

/**
 * Modify cube schema with Tenant ID.  Tenant ID comes from the user name 
 * created by OAuthSSO single signon.
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


public class ParameterDynamicSchemaProcessor
    extends FilterDynamicSchemaProcessor
    implements DynamicSchemaProcessor
{
    private static final Logger logger =
        Logger.getLogger(ParameterDynamicSchemaProcessor.class);

    /**
     * Property parameter pattern
     */
    private String parameterPattern = "[organization]";

    /** Creates a new instance of LocalizingDynamicSchemaProcessor */
    public ParameterDynamicSchemaProcessor() {
    }

    public String filter(
        String schemaUrl,
        Util.PropertyList connectInfo,
        InputStream stream) throws Exception
    {
        String schema = super.filter(schemaUrl, connectInfo, stream);
        schema = doReplacements(schema);
        return schema;
    }

    private String doReplacements(String schema) {
    	
    	//  Looks like session is not updated with user name after Authentication is
    	//  created.  Use Authentication instead.
    	//String userId = PentahoSessionHolder.getSession().getName();
   	
    	String userId = SecurityContextHolder.getContext().getAuthentication().getName();
    	
    	int separator = userId.indexOf("-");
    	String tenantId;
    	if (separator == -1) {
    		tenantId ="";
    	}
    	else {
    		tenantId = userId.substring(separator +1);
    	}
        String schemaOut = schema.replace(parameterPattern, tenantId);
		if (ParameterDynamicSchemaProcessor.logger.isDebugEnabled()) {
			ParameterDynamicSchemaProcessor.logger.debug((
			"ParameterDynamicSchemaProcessor.GENERATING_SCHEMA_WITH _ID " + tenantId)); //$NON-NLS-1$
		}
        return schemaOut;
    }

    public String getparameterPattern() {
        return this.parameterPattern;
    }

    public void setparameterPattern(String parameterPattern) {
        this.parameterPattern = parameterPattern;
    }
}


