/*
 *   Given a Days date since 1900/01/01 return a date string yyy/MM/dd
 *
 *  Copyright 0x00A9 2011 Jeff Gunderson
 *  Licensed under the GNU Public License, Version 3.0.
 *  You may obtain a copy of the GPL V3 License at http://www.gnu.org/licenses/lgpl-3.0.html
 *
*/

package com.erpbi; 

import mondrian.olap.Evaluator;
import mondrian.olap.Syntax;
import mondrian.olap.type.Type;
import mondrian.olap.type.StringType;
import mondrian.olap.type.NumericType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;


public class GetDateInfo implements mondrian.spi.UserDefinedFunction
{
    private String udfName;
    private String returnString;
    protected final Log log = LogFactory.getLog(this.getClass());

    public GetDateInfo(String name)
    {
        udfName = name;
        log.info("constructor, udfName: "+udfName);
    }

    public Object execute(Evaluator evaluator, Argument[] arguments)
    {
        synchronized(this)
        {
             if (udfName.equals("getDateString"))
             {
                // get input string as int
                Object oDays = arguments[0].evaluate(evaluator);
                String sDays = oDays.toString();
                float fDays = Float.parseFloat(sDays);
                int iDays = (int)fDays;
                // create Calendar starting at 1900/01/01 and bump by input days
                Calendar c = Calendar.getInstance();
                c.set(1900, 00, 01);
                c.add(Calendar.DATE, iDays);  

                // format date string
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
                returnString = sdf.format(c.getTime());  
             }  
            else if (udfName.equals("getCurrentDays"))
             {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
                Date today = new Date();
                long d1 = 0;
                
                try {
                  d1 = sdf.parse("1900/01/01").getTime();
                }
       			catch(Exception e) {
        		  e.printStackTrace(System.out);
       			}
                long d2 = today.getTime();

                returnString =  "" + Math.abs((d2-d1)/(1000*60*60*24));
             }
             else
             {
                    returnString = "";
             }

            if (log.isDebugEnabled())
            {
                log.debug(" returnString: "+returnString);
            }

        return returnString;
        }
    }


    public String getDescription() {
        return "Date functions";
    }

    public String getName() {
        return udfName;
    }

    public Type[] getParameterTypes() {
        return new Type[] {
            new StringType()
        };
    }

    public String[] getReservedWords() {
        return null;
    }

    public Type getReturnType(Type[] parameterTypes) {
        return new StringType();
    }

    public Syntax getSyntax() {
        return Syntax.Function;
    }

}
