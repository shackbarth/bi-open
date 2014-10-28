package com.xtuple.utils;
import java.util.List;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import org.pentaho.platform.plugin.action.mondrian.catalog.MondrianCatalogHelper;
import org.pentaho.platform.plugin.action.mondrian.catalog.MondrianCatalog;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
/**
 * Refresh OLAP Cache after webapp deployement.  See web.xml for listener definition.
 *  
 * @author Jeff Gunderson
 *
 */
 
public class RefreshOLAPCache implements ServletContextListener{
	
	//~ Static fields/initializers =============================================

	private static final Log logger = LogFactory.getLog(RefreshOLAPCache.class);
 
	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
	}
 
	@Override
	public void contextInitialized(ServletContextEvent arg0) {
        RefreshOLAPCache.logger.warn("OLAP cache cleared at startup.  See RefreshOLAPCache in web.xml");
		MondrianCatalogHelper helper = MondrianCatalogHelper.getInstance();
		helper.reInit(null);
	}
}