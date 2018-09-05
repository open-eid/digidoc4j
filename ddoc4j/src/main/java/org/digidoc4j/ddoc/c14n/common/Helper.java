package org.digidoc4j.ddoc.c14n.common;

import java.text.SimpleDateFormat;
import java.util.Date;

public final class Helper {

    public static Date get_BuildDate()
    {
        SimpleDateFormat sdf;
        Date myDate;

        sdf = new SimpleDateFormat("dd.MM.yyyy h:mm:ss z");
        myDate = null;
        try
        {
            myDate = sdf.parse(Helper.get_BuildDateString());
        }
        catch (Throwable __exc)
        {
        }

        return myDate;
    }

    /**
     * gets the hard coded build date
     */
    public static String get_BuildDateString()
    {
        return "5.06.2006 8:08:57 UTC";
    }

    /**
     * gets the hard coded compiler build date
     */
    public static String get_CompilerBuildDateString()
    {
        return "5.06.2006 8:08:38 UTC";
    }

    public static boolean IsVisibleChar(int p)
    {
        boolean bA;
        boolean aZ;
        boolean lA;
        boolean buA;
        boolean auZ;
        boolean uA;
        boolean b0;
        boolean a9;
        boolean uN;
        boolean x;
        boolean isAlpha;

        bA = !(p < 97);
        aZ = !(p > 122);
        lA = (bA && aZ);
        buA = !(p < 65);
        auZ = !(p > 90);
        uA = (buA && auZ);
        b0 = !(p < 48);
        a9 = !(p > 57);
        uN = (b0 && a9);
        x = ("\'\"=[]()<>+-;:.?\u0040/".indexOf(((char)p)) > -1);
        isAlpha = (lA || (uA || (uN || x)));
        return isAlpha;
    }

    public static Runtime get_CurrentRuntime()
    {
        return Runtime.getRuntime();
    }

    public static String get_UsedMemoryPercentage()
    {
        return new Integer(Convert.ToInt16(((Helper.get_UsedMemory() * ((long)100)) / Helper.get_CurrentRuntime().totalMemory())))+ "%";
    }

    public static long get_UsedMemory()
    {
        return (Helper.get_CurrentRuntime().totalMemory() - Helper.get_CurrentRuntime().freeMemory());
    }

    public static String get_TotalMemoryString()
    {
        return Convert.BytesToHuman(Helper.get_CurrentRuntime().totalMemory());
    }

    public static String get_MemoryUsageString()
    {
        Object[] objectArray1;

        objectArray1 = new Object[]
            {
                Helper.get_UsedMemoryPercentage(),
                " of ",
                Helper.get_TotalMemoryString(),
                " (",
                new Long(Helper.get_CurrentRuntime().totalMemory()),
                " bytes)"
            };
        return StringImplementation.Concat(objectArray1);
    }

}
