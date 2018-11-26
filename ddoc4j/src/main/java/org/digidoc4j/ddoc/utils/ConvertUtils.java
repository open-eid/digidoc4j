package org.digidoc4j.ddoc.utils;

import org.apache.log4j.Logger;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.tsl.MultiLangString;

import javax.security.auth.x500.X500Principal;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.*;

public class ConvertUtils
{
    private static final String m_dateFormat = "yyyy.MM.dd'T'HH:mm:ss'Z'";
    private static final String m_dateFormatXAdES = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static final String m_dateFormatIso8601 = "yyyy.MM.dd'T'HH:mm:ss";
    private static final String m_dateFormatSSS = "yyyy.MM.dd'T'HH:mm:ss.SSS'Z'";
    private static final String m_dateFormatXAdESSSS = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    private static Logger m_logger = Logger.getLogger(ConvertUtils.class);
    public static final String X509_NAME_RFC = "RFC2253"; //"RFC4514";
    /** Invalid SHA1 13+0x00 algortihm prefix - 00 30 21 30 09 06 05 2b 0e 03 02 1a 04 14 0x00 */
    private static final byte[] sha1AlgPrefix13Bad = {
            0x30, 0x1f, 0x30, 0x07, 0x06,
            0x05, 0x2b, 0x0e, 0x03, 0x02,
            0x1a, 0x04, 0x14, 0x00 };
    /** Invalid SHA1 15+0x00 algortihm prefix - 00 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 0x00 */
    private static final byte[] sha1AlgPrefix15Bad = {
            0x30, 0x21, 0x30, 0x09, 0x06,
            0x05, 0x2b, 0x0e, 0x03, 0x02,
            0x1a, 0x05, 0x00, 0x04, 0x14, 0x00 };
    /** SHA1 algortihm prefix - 00 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14  */
    private static final byte[] sha1AlgPrefix1 = { // long
            0x30, 0x21, 0x30, 0x09, 0x06,
            0x05, 0x2b, 0x0e, 0x03, 0x02,
            0x1a, 0x05, 0x00, 0x04, 0x14 };
    private static final byte[] sha1AlgPrefix2 = { // short
            0x30, 0x1f, 0x30, 0x07, 0x06,
            0x05, 0x2b, 0x0e, 0x03, 0x02,
            0x1a, 0x04, 0x14 };

    /**
     * Helper method to convert a Date
     * object to xsd:date format
     * @param d input data
     * @param ddoc signed doc
     * @return stringified date (xsd:date)
     * @throws DigiDocException for errors
     */
    public static String date2string(Date d, SignedDoc ddoc)
            throws DigiDocException
    {
        String str = null, sF = null;
        try {
            if(d != null) {
                sF = ddoc.getVersion().equals(SignedDoc.VERSION_1_3) ? m_dateFormatXAdES : m_dateFormat;
                SimpleDateFormat f = new SimpleDateFormat(sF);
                f.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
                str = f.format(d);
            }
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_DATE_FORMAT);
        }
        return str;
    }

    public static String convX509Name(X500Principal principal)
    {
        String sName = principal.getName(X509_NAME_RFC);
        return sName;
    }

    public static String getTrace(Throwable ex)
    {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        ex.printStackTrace(pw);
        return sw.toString();
    }

    public static boolean compareBytes(byte[] srch, byte[] from, int idx1)
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Find: \'" + SignedDoc.bin2hex(srch) + "\' int: \'" + SignedDoc.bin2hex(from) + "\' starting: " + idx1);
        if(srch != null && from != null && idx1 >= 0 && ((idx1 + srch.length) < from.length)) {
            for(int i = idx1; i < idx1 + srch.length; i++) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Pos: " + i +  " " + from[i] + " - " + srch[i-idx1]);
                if(from[i] != srch[i-idx1])
                    return false;
            }
            return true;
        }
        return false;
    }

    public static String findDigType(byte[] digest)
    {
        if((compareBytes(sha1AlgPrefix13Bad, digest, 0) && digest.length == 34) ||
                (compareBytes(sha1AlgPrefix15Bad, digest, 0) && digest.length == 36))
            return SignedDoc.SHA1_DIGEST_TYPE_BAD;
        if(compareBytes(sha1AlgPrefix1, digest, 0) ||
                compareBytes(sha1AlgPrefix2, digest, 0))
            return SignedDoc.SHA1_DIGEST_TYPE;
        return null;
    }

    public static byte[] removePrefix(byte[] digest)
    {
        int nLen = 0;
        if(compareBytes(sha1AlgPrefix1, digest, 0))
            nLen = sha1AlgPrefix1.length;
        else if(compareBytes(sha1AlgPrefix2, digest, 0))
            nLen = sha1AlgPrefix2.length;
        if(nLen > 0) {
            byte[] ndig = new byte[digest.length - nLen];
            System.arraycopy(digest,
                    digest.length - ndig.length,
                    ndig, 0, ndig.length);
            return ndig;
        }
        return null;
    }

    /**
     * Helper method to convert a string
     * to a Date object from xsd:date format
     * @param str stringified date (xsd:date
     * @param ddoc signed doc
     * @return Date object
     * @throws DigiDocException for errors
     */
    public static Date string2date(String str, SignedDoc ddoc)
            throws DigiDocException
    {
        Date d = null;
        String sF = null;
        try {
            sF = ddoc.getVersion().equals(SignedDoc.VERSION_1_3) ? m_dateFormatXAdES :
                    (ddoc.getFormat().equals(SignedDoc.FORMAT_SK_XML) ? m_dateFormatIso8601 : m_dateFormat);
            SimpleDateFormat f = new SimpleDateFormat(sF);
            if(!ddoc.getFormat().equals(SignedDoc.FORMAT_SK_XML))
                f.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
            if(str != null && str.length() > 0)
                d = f.parse(str.trim());
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_DATE_FORMAT);
        }
        return d;
    }

    /**
     * Helper method to convert a string
     * to a Date object from xsd:date format
     * @param str stringified date (xsd:date
     * @return Date object
     * @throws DigiDocException for errors
     */
    public static Date str2date(String str)
    {
        Date d = null;
        try {
            // use default value to get a meaningful error message
            SimpleDateFormat f = new SimpleDateFormat(m_dateFormatXAdES);
            // test other possibilities
            if(str != null && str.length() >= 20 && str.charAt(10) == 'T') {
                if(str.charAt(4) == '-' && str.charAt(7) == '-') {
                    if(str.length() > 20)
                        f = new SimpleDateFormat(m_dateFormatXAdESSSS);
                    else
                        f = new SimpleDateFormat(m_dateFormatXAdES);
                }
                if(str.charAt(4) == '.' && str.charAt(7) == '.') {
                    if(str.length() > 20) {
                        if(str.charAt(20) == '-')
                            f = new SimpleDateFormat(m_dateFormatIso8601);
                        else
                            f = new SimpleDateFormat(m_dateFormatSSS);
                    } else
                        f = new SimpleDateFormat(m_dateFormat);
                }
                f.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
                d = f.parse(str.trim());
            }
        } catch(Exception ex) {
            m_logger.error("Error parsing date: " + str + " - " + ex);
        }
        return d;
    }

    /**
     * Helper method to convert a string
     * to a BigInteger object
     * @param str stringified date (xsd:date
     * @return BigInteger object
     * @throws DigiDocException for errors
     */
    public static BigInteger string2bigint(String str)
            throws DigiDocException
    {
        BigInteger b = null;
        try {
            if(str != null && str.length() > 0)
                b = new BigInteger(str.trim());
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_NUMBER_FORMAT);
        }
        return b;
    }

    /**
     * Helper method to convert a String
     * to UTF-8
     * @param data input data
     * @param codepage codepage of input bytes
     * @return UTF-8 string
     * @throws DigiDocException for errors
     */
    public static byte[] data2utf8(byte[] data, String codepage)
            throws DigiDocException
    {
        byte[] bdata = null;
        try {
            String str = new String(data, codepage);
            bdata = str.getBytes("UTF-8");
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return bdata;
    }

    /**
     * Converts to UTF-8 byte array
     * @param str input data
     * @return byte array of string in desired codepage
     * @throws DigiDocException for errors
     */
    public static byte[] str2data(String str)
            throws DigiDocException
    {
        return str2data(str, "UTF-8");
    }

    /**
     * Helper method to convert a String
     * to byte array of any codepage
     * @param data input data
     * @param codepage codepage of output bytes
     * @return byte array of string in desired codepage
     * @throws DigiDocException for errors
     */
    public static byte[] str2data(String str, String codepage)
            throws DigiDocException
    {
        byte[] bdata = null;
        try {
            bdata = str.getBytes(codepage);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return bdata;
    }

    /**
     * Helper method to convert a String
     * to UTF-8
     * @param data input data
     * @param codepage codepage of input bytes
     * @return UTF-8 string
     * @throws DigiDocException for errors
     */
    public static String data2str(byte[] data, String codepage)
            throws DigiDocException
    {
        String str = null;
        try {
            str = new String(data, codepage);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return str;
    }

    /**
     * Checks if the certificate identified by this CN is
     * a known OCSP responders cert
     * @param cn certificates common name
     * @return true if this is a known OCSP cert
     */
    public static boolean isKnownOCSPCert(String cn)
    {
        int nOcsps = ConfigManager.instance().getIntProperty("DIGIDOC_OCSP_COUNT", 0);
        //if(m_logger.isDebugEnabled())
        //	m_logger.debug("OCSPs: " + nOcsps);
        for(int i = 0; i < nOcsps; i++) {
            String s = ConfigManager.instance().getProperty("DIGIDOC_OCSP" + (i+1) + "_CN");
            //if(m_logger.isDebugEnabled())
            //	m_logger.debug("DIGIDOC_OCSP" + (i+1) + "_CN" + "=>" + s);
            if(s != null && s.equals(cn))
                return true;
        }
        return false;
    }

    /**
     * Checks if the certificate identified by this CN is
     * a known TSA cert
     * @param cn certificates common name
     * @return true if this is a known TSA cert
     */
    public static boolean isKnownTSACert(String cn)
    {
        int nTsas = ConfigManager.instance().getIntProperty("DIGIDOC_TSA_COUNT", 0);
        for(int i = 0; i < nTsas; i++) {
            String s = ConfigManager.instance().getProperty("DIGIDOC_TSA" + (i+1) + "_CN");
            if(s != null && s.equals(cn))
                return true;
        }
        return false;
    }

    /**
     * return CN part of DN
     * @return CN part of DN or null
     */
    public static String getCommonName(String dn) {
        String name = null;
        if(m_logger.isDebugEnabled())
            m_logger.debug("DN: " + dn);
        if(dn != null) {
            int idx1 = dn.indexOf("CN=");
            if(idx1 != -1) {
                idx1 += 2;
                while(idx1 < dn.length() &&
                        !Character.isLetter(dn.charAt(idx1)))
                    idx1++;
                int idx2 = idx1;
                while(idx2 < dn.length() &&
                        dn.charAt(idx2) != '\"' &&
                        dn.charAt(idx2) != '\\' &&
                        (dn.charAt(idx2) != ',' /*|| dn.charAt(idx2-1) != '\\'*/) &&
                        dn.charAt(idx2) != '/')
                    idx2++;
                name = dn.substring(idx1, idx2);
            }
        }
        return name;
    }

    /**
     * Converts a byte array to hex string
     * @param arr byte array input data
     * @return hex string
     */
    public static String bin2hex(byte[] arr)
    {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < arr.length; i++) {
            String str = Integer.toHexString((int)arr[i]);
            if(str.length() == 2)
                sb.append(str);
            if(str.length() < 2) {
                sb.append("0");
                sb.append(str);
            }
            if(str.length() > 2)
                sb.append(str.substring(str.length()-2));
        }
        return sb.toString();
    }

    public static String uriDecode(String s1)
    {
        if(s1 == null || s1.length() == 0)
            return s1;
        try {
            String s = s1;
            s = replaceStr(s, '+', "%2B");
            s = URLDecoder.decode(s, "UTF-8");
            if(m_logger.isDebugEnabled())
                m_logger.debug("URI: " + s1 + " decoded: " + s);
            return s;
        } catch(Exception ex) {
            m_logger.error("Error decoding bytes: " + ex);
        }
        return null;
    }

    private static String replaceStr(String src, char c1, String rep)
    {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; (src != null) && (i < src.length()); i++) {
            char c2 = src.charAt(i);
            if(c2 == c1)
                sb.append(rep);
            else
                sb.append(c2);
        }
        return sb.toString();
    }

    /*
    Not converting:
    (From RFC  RFC 3986 "URI Generic Syntax")
    unreserved    = ALPHA / DIGIT / “-” / “.” / “_” / “~”
    gen-delims = “:” / “/” / “?” / “#” / “[” / “]” / “@”
    sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
    */
    public static String uriEncodePath(String s1)
    {
        try {
            String s = s1;
            //s = replaceStr(s, '[', "%5B");
            //s = replaceStr(s, ']', "%5D");
            if(m_logger.isDebugEnabled())
                m_logger.debug("Before uri-path-enc: " + s);
            s = URLEncoder.encode(s, "UTF-8");
            s = replaceStr(s, '+', "%20");
            s = s.replaceAll("%7E", "~");
            // the following chars are not restored for compatibility with CPP and Digidoc4j
// 		s = s.replaceAll("%26", Matcher.quoteReplacement("&amp;"));
// 		s = s.replaceAll("%21", "!");
//		  s = s.replaceAll("%40", "@");
//		  s = s.replaceAll("%27", "\'");
//		  s = s.replaceAll("%24", Matcher.quoteReplacement("$"));
//		  s = s.replaceAll("%28", "(");
//		  s = s.replaceAll("%29", ")");
//		  s = s.replaceAll("%3D", "=");
//		  s = s.replaceAll("%2B", "+");
//		  s = s.replaceAll("%2C", ",");
//	      s = s.replaceAll("%3B", ";");
//	      s = s.replaceAll("%2F", "/");
//	      s = s.replaceAll("%3F", "?");

            if(m_logger.isDebugEnabled())
                m_logger.debug("URI path: " + s1 + " encoded: " + s);
            return s;
        } catch(Exception ex) {
            m_logger.error("Error encoding path: " + ex);
        }
        return null;
    }

    public static String escapeXmlSymbols(String s1)
    {
        if(s1 == null || s1.length() == 0)
            return s1;
        StringBuffer sb = new StringBuffer();
        try {
            for(int i = 0; i < s1.length(); i++) {
                char c1 = s1.charAt(i);
                if(c1 == '&') {
                    sb.append("&amp;");
                } else if(c1 == '<') {
                    sb.append("&lt;");
                } else if(c1 == '>') {
                    sb.append("&gt;");
                } else if(c1 == '\r') {
                    sb.append("&#xD;");
                } else if(c1 == '\'') {
                    sb.append("&apos;");
                } else if(c1 == '\"') {
                    sb.append("&quot;");
                } else
                    sb.append(c1);
            }
        } catch(Exception ex) {
            m_logger.error("Error converting bytes: " + ex);
        }
        return sb.toString();
    }

    public static String escapeTextNode(String s1)
    {
        if(s1 == null || s1.length() == 0)
            return s1;
        StringBuffer sb = new StringBuffer();
        try {
            for(int i = 0; i < s1.length(); i++) {
                char c1 = s1.charAt(i);
                if(c1 == '&') {
                    sb.append("&amp;");
                } else if(c1 == '<') {
                    sb.append("&lt;");
                } else if(c1 == '>') {
                    sb.append("&gt;");
                } else if(c1 == '\r') {
                    sb.append("&#xD;");
                } else
                    sb.append(c1);
            }
        } catch(Exception ex) {
            m_logger.error("Error converting bytes: " + ex);
        }
        return sb.toString();
    }

    public static String unescapeXmlSymbols(String s1)
    {
        String s2 = s1.replaceAll("&lt;", "<");
        s2 = s2.replaceAll("&gt;", ">");
        s2 = s2.replaceAll("&gt;", ">");
        s2 = s2.replaceAll("&#xD;", "\r");
        s2 = s2.replaceAll("&apos;", "'");
        s2 = s2.replaceAll("&quot;", "\"");
        s2 = s2.replaceAll("&amp;", "&");
        s2 = s2.replaceAll("&#xA;", "\n");
        return s2;
    }

    /**
     * Returns a string representation of an int element
     * with it's value for debug & log purposes
     * @param name element name
     * @param value elements value
     * @return stringified element representation
     */
    public static String intElemToString(String name, int value)
    {
        StringBuffer sb = new StringBuffer();
        if(value != 0) {
            sb.append("(");
            sb.append(name);
            sb.append("=");
            sb.append(value);
            sb.append(")");
        }
        return sb.toString();
    }

    /**
     * Returns a string representation of a string element
     * with it's value for debug & log purposes
     * @param name element name
     * @param value elements value
     * @return stringified element representation
     */
    public static String stringElemToString(String name, String value)
    {
        StringBuffer sb = new StringBuffer();
        if(value != null) {
            sb.append("(");
            sb.append(name);
            sb.append("=");
            sb.append(value);
            sb.append(")");
        }
        return sb.toString();
    }

    /**
     * Returns a string representation of a date element
     * with it's value for debug & log purposes
     * @param name element name
     * @param value elements value
     * @return stringified element representation
     */
    public static String dateElemToString(String name, Date value)
    {
        StringBuffer sb = new StringBuffer();
        if(value != null) {
            sb.append("(");
            sb.append(name);
            sb.append("=");
            Calendar cal = Calendar.getInstance();
            cal.setTime(value);
            sb.append(cal.get(Calendar.DAY_OF_MONTH));
            sb.append(".");
            sb.append(cal.get(Calendar.MONTH)+1);
            sb.append(".");
            sb.append(cal.get(Calendar.YEAR));
            sb.append(")");
        }
        return sb.toString();
    }

    /**
     * Converts a List of MultiLangStrings to array
     * @param l List object
     * @return array of MultiLangString objects
     */
    public static MultiLangString[] list2mls(List l) {
        MultiLangString[] arr = null;
        if(l != null && l.size() > 0) {
            arr = new MultiLangString[l.size()];
            for(int i = 0; i < l.size(); i++)
                arr[i] = (MultiLangString)l.get(i);
        }
        return arr;
    }

    /**
     * Converts a List of Datew to array
     * @param l List object
     * @return array of Date objects
     */
    public static Date[] list2dates(List l) {
        Date[] arr = null;
        if(l != null && l.size() > 0) {
            arr = new Date[l.size()];
            for(int i = 0; i < l.size(); i++)
                arr[i] = (Date)l.get(i);
        }
        return arr;
    }

    /**
     * Converts a List of String to array
     * @param l List object
     * @return array of String objects
     */
    public static String[] list2strings(List l) {
        String[] arr = null;
        if(l != null && l.size() > 0) {
            arr = new String[l.size()];
            for(int i = 0; i < l.size(); i++)
                arr[i] = (String)l.get(i);
        }
        return arr;
    }

    public static List addObject(List l, Object o) {
        if(l == null)
            l = new ArrayList();
        l.add(o);
        return l;
    }

    /**
     * Returns a MultiLangString from List
     * @param l List object
     * @param n index
     * @return MultiLangString object or null
     */
    public static MultiLangString getListObj(List l, int n) {
        if(l != null && n >= 0 && n < l.size())
            return (MultiLangString)l.get(n);
        else
            return null;
    }

    /**
     * Returns a String from List
     * @param l List object
     * @param n index
     * @return String object or null
     */
    public static String getListString(List l, int n) {
        if(l != null && n >= 0 && n < l.size())
            return (String)l.get(n);
        else
            return null;
    }

}
