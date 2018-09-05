package org.digidoc4j.ddoc.utils;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.tsl.MultiLangString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;

public class ConvertUtils
{
    private static final String m_dateFormat = "yyyy.MM.dd'T'HH:mm:ss'Z'";
    private static final String m_dateFormatXAdES = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static final String m_dateFormatIso8601 = "yyyy.MM.dd'T'HH:mm:ss";
    private static final String m_dateFormatSSS = "yyyy.MM.dd'T'HH:mm:ss.SSS'Z'";
    private static final String m_dateFormatXAdESSSS = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    private static Logger m_logger = LoggerFactory.getLogger(ConvertUtils.class);
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
    /** SHA224 prefix - 00302d300d06096086480165030402040500041c */
    private static final byte[] sha224AlgPrefix1 = { // long
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
            (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1c };
    private static final byte[] sha224AlgPrefix2 = { // short
            0x30, 0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60,
            (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x04, 0x1c };
    /** sha256 alg prefix - 003031300d060960864801650304020105000420 5ad8f86f90558d973aba4ce9be116646efd2c57758e5238b841d50abe788bae9 */
    private static final byte[] sha256AlgPrefix1 = { // long
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };
    private static final byte[] sha256AlgPrefix2 = { // short
            0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20
    };
    private static final byte[] sha512AlgPrefix1 =   // long
            { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
    private static final byte[] sha512AlgPrefix2 =    // short
            { 0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04, 0x40 };


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
                sF = (ddoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ||
                        (ddoc.getVersion().equals(SignedDoc.VERSION_1_3)) ? m_dateFormatXAdES : m_dateFormat);
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

    /**
     * Adds ASN.1 structure prefix to digest value to be signed
     * @param digest digest value to be signed
     * @return prefixed digest value
     */
    public static byte[] addDigestAsn1Prefix(byte[] digest)
    {
        byte[] ddata = null;
    	/*if(digest.length == SignedDoc.SHA1_DIGEST_LENGTH) {
      	  ddata = new byte[sha1AlgPrefix.length + digest.length + 1];
      	  System.arraycopy(sha1AlgPrefix, 0, ddata, 0, sha1AlgPrefix.length);
      	  System.arraycopy(digest, 0, ddata,
      			sha1AlgPrefix.length + 1, digest.length);
      	}*/
        if(digest.length == SignedDoc.SHA1_DIGEST_LENGTH) {
            ddata = new byte[sha1AlgPrefix1.length + digest.length];
            System.arraycopy(sha1AlgPrefix1, 0, ddata, 0, sha1AlgPrefix1.length);
            System.arraycopy(digest, 0, ddata,
                    sha1AlgPrefix1.length, digest.length);
        }
        if(digest.length == SignedDoc.SHA224_DIGEST_LENGTH) {
            ddata = new byte[sha224AlgPrefix1.length + digest.length];
            System.arraycopy(sha224AlgPrefix1, 0, ddata, 0, sha224AlgPrefix1.length);
            System.arraycopy(digest, 0, ddata,
                    sha224AlgPrefix1.length, digest.length);
        }
        if(digest.length == SignedDoc.SHA256_DIGEST_LENGTH) {
            ddata = new byte[sha256AlgPrefix1.length + digest.length];
            System.arraycopy(sha256AlgPrefix1, 0, ddata, 0, sha256AlgPrefix1.length);
            System.arraycopy(digest, 0, ddata,
                    sha256AlgPrefix1.length, digest.length);
        }
        if(digest.length == SignedDoc.SHA512_DIGEST_LENGTH) {
            ddata = new byte[sha512AlgPrefix1.length + digest.length];
            System.arraycopy(sha512AlgPrefix1, 0, ddata, 0, sha512AlgPrefix1.length);
            System.arraycopy(digest, 0, ddata,
                    sha512AlgPrefix1.length, digest.length);
        }
        return ddata;
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

    public static String findNonceDigType(byte[] digest)
    {
        if(digest.length == SignedDoc.SHA1_DIGEST_LENGTH + 2)
            return SignedDoc.SHA1_DIGEST_TYPE;
        if(digest.length == SignedDoc.SHA224_DIGEST_LENGTH + 2)
            return SignedDoc.SHA224_DIGEST_TYPE;
        if(digest.length == SignedDoc.SHA256_DIGEST_LENGTH + 2)
            return SignedDoc.SHA256_DIGEST_TYPE;
        if(digest.length == SignedDoc.SHA512_DIGEST_LENGTH + 2)
            return SignedDoc.SHA512_DIGEST_TYPE;
        return null;
    }

    public static String findDigType(byte[] digest)
    {
        if((compareBytes(sha1AlgPrefix13Bad, digest, 0) && digest.length == 34) ||
                (compareBytes(sha1AlgPrefix15Bad, digest, 0) && digest.length == 36))
            return SignedDoc.SHA1_DIGEST_TYPE_BAD;
        if(compareBytes(sha1AlgPrefix1, digest, 0) ||
                compareBytes(sha1AlgPrefix2, digest, 0))
            return SignedDoc.SHA1_DIGEST_TYPE;
        if(compareBytes(sha224AlgPrefix1, digest, 0) ||
                compareBytes(sha224AlgPrefix2, digest, 0))
            return SignedDoc.SHA224_DIGEST_TYPE;
        if(compareBytes(sha256AlgPrefix1, digest, 0) ||
                compareBytes(sha256AlgPrefix2, digest, 0))
            return SignedDoc.SHA256_DIGEST_TYPE;
        if(compareBytes(sha512AlgPrefix1, digest, 0) ||
                compareBytes(sha512AlgPrefix2, digest, 0))
            return SignedDoc.SHA512_DIGEST_TYPE;
        return null;
    }

    public static byte[] removePrefix(byte[] digest)
    {
        int nLen = 0;
        if(compareBytes(sha1AlgPrefix1, digest, 0))
            nLen = sha1AlgPrefix1.length;
        else if(compareBytes(sha1AlgPrefix2, digest, 0))
            nLen = sha1AlgPrefix2.length;
        else if(compareBytes(sha224AlgPrefix1, digest, 0))
            nLen = sha224AlgPrefix1.length;
        else if(compareBytes(sha224AlgPrefix2, digest, 0))
            nLen = sha224AlgPrefix2.length;
        else if(compareBytes(sha256AlgPrefix1, digest, 0))
            nLen = sha256AlgPrefix1.length;
        else if(compareBytes(sha256AlgPrefix2, digest, 0))
            nLen = sha256AlgPrefix2.length;
        else if(compareBytes(sha512AlgPrefix1, digest, 0))
            nLen = sha512AlgPrefix1.length;
        else if(compareBytes(sha512AlgPrefix2, digest, 0))
            nLen = sha512AlgPrefix2.length;
        if(nLen > 0) {
            byte[] ndig = new byte[digest.length - nLen];
            System.arraycopy(digest,
                    digest.length - ndig.length,
                    ndig, 0, ndig.length);
            return ndig;
        }
        return null;
    }

    /*
     * IB-4056 this method was commented out because it requires caller to know
     * the prefix used. If this is not the case error will occur.
     * Use instead byte[] removePrefix(byte[] digest) that determines which prefix
     * is used before removing it.
     */
    /*public static byte[] removePrefixByType(byte[] digest, String digType)
    {
    	int nLen = 0;
    	if(digType.equals(SignedDoc.SHA1_DIGEST_TYPE))
    		nLen = sha1AlgPrefix1.length;
    	else if(digType.equals(SignedDoc.SHA224_DIGEST_TYPE))
    		nLen = sha224AlgPrefix1.length;
    	else if(digType.equals(SignedDoc.SHA256_DIGEST_TYPE))
    		nLen = sha256AlgPrefix1.length;
    	else if(digType.equals(SignedDoc.SHA512_DIGEST_TYPE))
    		nLen = sha512AlgPrefix1.length;
    	if(nLen > 0) {
    		byte[] ndig = new byte[digest.length - nLen];
    		System.arraycopy(digest,
                  	digest.length - ndig.length,
                  	ndig, 0, ndig.length);
    		return ndig;
    	}
    	return null;
    }*/

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
            sF = (ddoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ||
                    (ddoc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                            ddoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) ? m_dateFormatXAdES :
                    (ddoc.getFormat().equals(SignedDoc.FORMAT_SK_XML) ? m_dateFormatIso8601 : m_dateFormat));
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
     * Helper method to convert an UTF-8
     * String to non-utf8 string
     * @param UTF-8 input data
     * @return normal string
     * @throws DigiDocException for errors
     */
    public static String utf82str(String data)
            throws DigiDocException
    {
        String str = null;
        try {
            byte[] bdata = data.getBytes();
            str = new String(bdata, "UTF-8");
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

    public static void addKnownOCSPCert(String cn)
    {
        int nOcsps = ConfigManager.instance().getIntProperty("DIGIDOC_OCSP_COUNT", 0);
        //if(m_logger.isDebugEnabled())
        //	m_logger.debug("OCSPs: " + nOcsps);
        nOcsps++;
        String key = "DIGIDOC_OCSP" + nOcsps + "_CN";
        ConfigManager.instance().setStringProperty(key, cn);
        ConfigManager.instance().setStringProperty("DIGIDOC_OCSP_COUNT", new Integer(nOcsps).toString());
        //if(m_logger.isDebugEnabled())
        //	m_logger.debug(key + "=>" + cn + " count: " + nOcsps);
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

    public static void addKnownTSACert(String cn)
    {
        int nOcsps = ConfigManager.instance().getIntProperty("DIGIDOC_TSA_COUNT", 0);
        //if(m_logger.isDebugEnabled())
        //	m_logger.debug("OCSPs: " + nOcsps);
        nOcsps++;
        String key = "DIGIDOC_TSA" + nOcsps + "_CN";
        ConfigManager.instance().setStringProperty(key, cn);
        ConfigManager.instance().setStringProperty("DIGIDOC_TSA_COUNT", new Integer(nOcsps).toString());
        //if(m_logger.isDebugEnabled())
        //	m_logger.debug(key + "=>" + cn + " count: " + nOcsps);
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
     * return CN part of DN
     * @return CN part of DN or null
     */
    /*public static String getDnPart(X509Certificate cert, String attr) {
        String value = null;
        if(cert != null) {
        	Principal pr = cert.getSubjectDN();
        	pr.ge
        }
        return value;
    }*/

    /**
     * return CN part of DN
     * @return CN part of DN or null
     */
    public static String getDnPart(String dn, String attr) {
        String name = null;
        if(dn != null) {
            int idx1 = dn.indexOf(attr+ "=");
            if(idx1 != -1) {
                idx1 += attr.length() + 1;
            	/*while(idx1 < dn.length() &&
            		!Character.isLetter(dn.charAt(idx1)))
                	idx1++;*/
                int idx2 = idx1;
                while(idx2 < dn.length() &&
                        dn.charAt(idx2) != ',' &&
                        dn.charAt(idx2) != '/' &&
                        dn.charAt(idx2) != ' ')
                    idx2++;
                name = dn.substring(idx1, idx2);
            }
        }
        return name;
    }


    public static byte[] getBytesFromFile(File file ) throws IOException {
        InputStream is = new FileInputStream(file);

        // Get the size of the file
        long length = file.length();

        if (length > Integer.MAX_VALUE) {
            // File is too large
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
                && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
            offset += numRead;
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }

        // Close the input stream and return bytes
        is.close();
        return bytes;
    }




    /**
     * Converts a hex string to byte array
     * @param hexString input data
     * @return byte array
     */
    public static byte[] hex2bin(String hexString)
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            for(int i = 0; (hexString != null) &&
                    (i < hexString.length()); i += 2) {
                String tmp = hexString.substring(i, i+2);
                Integer x = new Integer(Integer.parseInt(tmp, 16));
                bos.write(x.byteValue());
            }
        } catch(Exception ex) {
            m_logger.error("Error converting hex string: " + ex);
        }
        return bos.toByteArray();
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

    private static final String hexChars = "0123456789ABCDEF";

    public static boolean isHexDigit(char c) {
        char c2 = Character.toUpperCase(c);
        for(int i = 0; i < hexChars.length(); i++)
            if(hexChars.charAt(i) == c2)
                return true;
        return false;
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
    (From RFC 2396 "URI Generic Syntax")
    reserved = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "$" | ","
    mark     = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
     */
    public static String uriEncode(String s1)
    {
        try {
            String s = s1;
            //s = replaceStr(s, '[', "%5B");
            //s = replaceStr(s, ']', "%5D");
            if(m_logger.isDebugEnabled())
                m_logger.debug("Before uri-enc: " + s);
            s = URLEncoder.encode(s, "UTF-8");
            s = replaceStr(s, '+', "%20");
            // restore mark chars that got converted
            s = s.replaceAll("%21", "!");
            s = s.replaceAll("%40", "@");
            s = s.replaceAll("%27", "\'");
            s = s.replaceAll("%24", Matcher.quoteReplacement("$"));
            s = s.replaceAll("%7E", "~");
            s = s.replaceAll("%26", Matcher.quoteReplacement("&amp;"));
            s = s.replaceAll("%28", "(");
            s = s.replaceAll("%29", ")");
            s = s.replaceAll("%3D", "=");
            s = s.replaceAll("%2B", "+");
            s = s.replaceAll("%2C", ",");
            s = s.replaceAll("%3B", ";");
            s = s.replaceAll("%2F", "/");
            s = s.replaceAll("%3F", "?");
            s = s.replaceAll("%3A", ":");
            if(m_logger.isDebugEnabled())
                m_logger.debug("URI: " + s1 + " encoded: " + s);
            return s;
        } catch(Exception ex) {
            m_logger.error("Error encoding bytes: " + ex);
        }
        return null;
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
     * Returns a string representation of an long element
     * with it's value for debug & log purposes
     * @param name element name
     * @param value elements value
     * @return stringified element representation
     */
    public static String longElemToString(String name, long value)
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
     * Returns a string representation of an double element
     * with it's value for debug & log purposes
     * @param name element name
     * @param value elements value
     * @return stringified element representation
     */
    public static String doubleElemToString(String name, double value)
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
     * Returns a string representation of a boolean element
     * with it's value for debug & log purposes
     * @param name element name
     * @param value elements value
     * @param bShowFalse show also false values or not
     * @return stringified element representation
     */
    public static String booleanElemToString(String name, boolean value, boolean bShowFalse)
    {
        StringBuffer sb = new StringBuffer();
        if(value || (!value && bShowFalse)) {
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

    /**
     * Checks if cert has certain key-usage bit set
     * @param cert certificate
     * @param nKu key-usage flag nr
     * @return true if set
     */
    public static boolean checkCertKeyUsage(X509Certificate cert, int nKu)
    {
        if(cert != null) {
            boolean keyUsages[] = cert.getKeyUsage();
            if(keyUsages != null && nKu >= 0 && keyUsages.length > nKu && keyUsages[nKu] == true)
                return true;
        }
        return false;
    }

    /**
     * Checks if cert has non-repud bit set
     * @param cert certificate
     * @return true if set
     */
    public static boolean isSignatureCert(X509Certificate cert)
    {
        return checkCertKeyUsage(cert, 1);
    }

    /**
     * Checks if cert has data-encryption bit set
     * @param cert certificate
     * @return true if set
     */
    public static boolean isEncryptCert(X509Certificate cert)
    {
        return checkCertKeyUsage(cert, 2);
    }

    /**
     * Checks if cert has cert-signing (CA) bit set
     * @param cert certificate
     * @return true if set
     */
    public static boolean isCACert(X509Certificate cert)
    {
        return checkCertKeyUsage(cert, 5);
    }

}
