package com.xtuple.utils;
import javax.print.PrintServiceLookup;
import javax.print.PrintService;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Get list of printers as json.  Example:
 * 
 * {"printers": [
 * {"name": "Microsoft XPS Document Writer"}
 * ,{"name": "Fax"}
 * ]}
 * 
 * @author Jeff Gunderson
 *
 */
 
public class Printers extends HttpServlet{

	public void doGet(HttpServletRequest request, HttpServletResponse response) {
	
		PrintService[] printers = PrintServiceLookup.lookupPrintServices(null, null);
		PrintWriter out;
		response.setContentType("application/json");
		
		try {		
			out = response.getWriter();
			out.println("{\"printers\": [");
	    	if (printers != null) {
	    		int i = 0;
	    		for (PrintService printer : printers) {
	    			if (printer != null) {
	    				if (i != 0) { out.println(","); };
	    				out.println("{\"name\": \"" + printer.getName() + "\"}");
	    			}
	    			i++;
	    		}
	    	}
	    	out.println("]}");
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}		

	}

}