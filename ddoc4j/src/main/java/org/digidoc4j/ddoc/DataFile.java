package org.digidoc4j.ddoc;

import org.digidoc4j.ddoc.factory.CanonicalizationFactory;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.ddoc.utils.ConvertUtils;
import org.apache.commons.codec.binary.Base64InputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;

/**
 * Represents a DataFile instance, that either
 * contains payload data or references and external
 * DataFile.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class DataFile implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** content type of the DataFile */
    private String m_contentType;
    /** filename */
    private String m_fileName;
    /** Id attribute of this DataFile */
    private String m_id;
    /** mime type of the file */
    private String m_mimeType;
    /** container comment (bdoc2 lib ver and name) */
    private String m_comment;
    /** file size on bytes */
    private long m_size;
    /** digest value of detatched file */
    private byte[] m_digestSha1;
    /** alternative (sha1) digest if requested */
    private byte[] m_digestAlt;

    /** digest value of the XML form of <DataFile>
     * If read from XML file then calculated immediately
     * otherwise on demand
     */
    private byte[] m_origDigestValue;
    /** additional attributes */
    private ArrayList m_attributes;
    /** data file contents in original form */
    private byte[] m_body;
    /** initial codepage of DataFile data */
    private String m_codepage;
    /** parent object reference */
    private SignedDoc m_sigDoc;

    /** allowed values for content type */
    public static final String CONTENT_EMBEDDED_BASE64 = "EMBEDDED_BASE64";
    public static final String CONTENT_BINARY = "BINARY";
    public static final String CONTENT_HASHCODE = "HASHCODE";

    /** the only allowed value for digest type */
    public static final String DIGEST_TYPE_SHA1 = "sha1";
    private static int block_size = 2048;
    /** log4j logger */
    private static Logger m_logger = LoggerFactory.getLogger(DataFile.class);
    /** temp file used to cache DataFile data if caching is enabled */
    private transient File m_fDfCache = null;
    private boolean m_bodyIsBase64;
    /** original input file last modified timestamp */
    private Date m_lModDt = null;


    /**
     * Creates new DataFile
     * @param id id of the DataFile
     * @param contenType DataFile content type
     * @param fileName original file name (without path!)
     * @param mimeType contents mime type
     * @param sdoc parent object
     * @throws DigiDocException for validation errors
     */
    public DataFile(String id, String contentType, String fileName, String mimeType, SignedDoc sdoc)
            throws DigiDocException
    {
        m_sigDoc = sdoc;
        setId(id);
        setContentType(contentType);
        setFileName(fileName);
        setMimeType(mimeType);
        m_size = 0;
        m_digestSha1 = null;
        m_attributes = null;
        m_body = null;
        m_codepage = "UTF-8";
        m_origDigestValue = null;
        m_fDfCache = null;
        m_bodyIsBase64 = false;
        m_comment = null;
    }

    /**
     * Accessor for temp file object used to cache DataFile data
     * if caching is enabled.
     * @return temp file object used to cache DataFile data
     */
    public File getDfCacheFile() {
        return m_fDfCache;
    }

    /**
     * Removes temporary DataFile cache file
     */
    public void cleanupDfCache() {
        if(m_fDfCache != null) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Removing cache file for df: " + m_fDfCache.getAbsolutePath());
            m_fDfCache.delete();
        }
        m_fDfCache = null;
    }

    /**
     * Accessor for body attribute.
     * Note that the body is normally NOT LOADED
     * from file and this attribute is empty!
     * @return value of body attribute
     */
    public byte[] getBody()
            throws DigiDocException
    {
        if(m_fDfCache != null) {
            try {
                byte[] data = SignedDoc.readFile(m_fDfCache);
                if(m_contentType.equals(CONTENT_EMBEDDED_BASE64))
                    data = Base64Util.decode(data);
                return data;
            } catch(Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
            }
        }
        return m_body;
    }

    /**
     * Mutator for body attribute. For
     * any bigger files don't use this method!
     * If you are using very small messages onthe other hand
     * then this might speed things up.
     * This method should not be publicly used to assign
     * data to body. If you do then you must also set the
     * initial codepage and size of body!
     * @param data new value for body attribute
     */
    public void setBody(byte[] data)
            throws DigiDocException
    {
        try {
            m_body = data;
            if(data != null) {
                m_size = data.length;
                storeInTempFile();
                if(m_contentType != null) {
                    if(m_contentType.equals(CONTENT_BINARY)) { // BDOC
                        if(!isDigestsCalculated()) {
                            if(m_body != null) // small amount of data in mem
                                calcHashes(new ByteArrayInputStream(m_body));
                            else if(m_fDfCache != null) // big amount of data moved to cache file
                                calcHashes(new FileInputStream(m_fDfCache));
                        }
                        if(m_mimeType != null) {
                            String sFile = m_fileName;
                            if(sFile != null && sFile.indexOf('/') != -1 || sFile.indexOf('\\') != -1) {
                                File fT = new File(sFile);
                                sFile = fT.getName();
                            }
                            if(m_sigDoc.findManifestEntryByPath(sFile) == null) {
                                ManifestFileEntry fe = new ManifestFileEntry(m_mimeType, sFile);
                                m_sigDoc.getManifest().addFileEntry(fe);
                            }
                        }
                    }
                    if(m_contentType.equals(CONTENT_EMBEDDED_BASE64)) { // DDOC
                        if(!isDigestsCalculated()) {
                            m_size = data.length;
                            m_body = Base64Util.encode(data).getBytes();
                            m_bodyIsBase64 = true;
                        }
                    }
                }
            }
        } catch(IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    public void setBase64Body(byte[] data)
    {
        if(data != null) {
            m_size = data.length;
            m_body = Base64Util.encode(data).getBytes();
            m_bodyIsBase64 = true;
        }
    }

    public void setBodyAsData(byte[] data, boolean b64, long len)
    {
        if(data != null) {
            m_size = len;
            m_body = data;
            m_bodyIsBase64 = b64;
        }
    }

    /**
     * Returnes true if body is already converted to base64
     * @return true if body is already converted to base64
     */
    public boolean getBodyIsBase64() { return m_bodyIsBase64; }

    /**
     * Set flag to indicate that body is already converted to base64
     * @param b flag to indicate that body is already converted to base64
     */
    public void setBodyIsBase64(boolean b) { m_bodyIsBase64 = b; }

    /**
     * Returnes content file last modified timestamp
     * @return last modified timestamp
     */
    public Date getLastModDt() { return m_lModDt; }

    /**
     * Set content file last modified timestamp
     * @param d last modified timestamp
     */
    public void setLastModDt(Date d) { m_lModDt = d; }




    /**
     * Sets DataFile contents from an input stream.
     * This method allways uses temporary files to read out
     * the input stream first in order to determine the
     * size of data. Caller can close the stream after
     * invoking this method because data has been copied.
     * Data is not yet converted to base64 (if required)
     * nor is the hash code calculated at this point.
     * Please not that data is stored in original binary format,
     * so getBody() etc. will not deliver correct result
     * until digidoc has been actually written to disk and read
     * in again.
     * @param is input stream delivering the data
     */
    public void setBodyFromStream(InputStream is)
            throws DigiDocException
    {
        if(is == null) return;
        // copy data to temp file
        try {
            File fCacheDir = new File(ConfigManager.instance().
                    getStringProperty("DIGIDOC_DF_CACHE_DIR", System.getProperty("java.io.tmpdir")));
            String dfId = new Long(System.currentTimeMillis()).toString();
            m_fDfCache = File.createTempFile(dfId, ".df", fCacheDir);
            FileOutputStream fos = new FileOutputStream(m_fDfCache);
            m_body = null;
            byte[] data = new byte[2048];
            int nRead = 0;
            m_size = 0;
            do {
                nRead = is.read(data);
                if(nRead > 0) {
                    fos.write(data, 0, nRead);
                    m_size += nRead;
                }
            } while(nRead > 0);
            fos.close();
            if(m_logger.isDebugEnabled())
                m_logger.debug("DF: " + m_id + " size: " + m_size + " cache-file: " + m_fDfCache.getAbsolutePath());
        } catch(IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    public boolean isDigestsCalculated()
    {
        return (m_digestSha1 != null);
    }

    /**
     * Calculate size and digests
     * @param is data input stream
     * @param os optional output stream to write read data to (cache file)
     */
    private void calcHashesAndWriteToStream(InputStream is, OutputStream os)
            throws DigiDocException
    {
        try {
            MessageDigest sha1 = MessageDigest.getInstance(SignedDoc.SHA1_DIGEST_TYPE);
            byte[] data = new byte[2048];
            int nRead = 0;
            m_size = 0;
            do {
                nRead = is.read(data);
                if(nRead > 0) {
                    sha1.update(data, 0, nRead);
                    if(os != null)
                        os.write(data, 0, nRead);
                    m_size += nRead;
                }
            } while(nRead > 0);
            m_digestSha1 = m_origDigestValue = sha1.digest();
            if(m_logger.isDebugEnabled())
                m_logger.debug("DF: " + m_id + " size: " + m_size +
                        " dig-sha1: " + Base64Util.encode(m_digestSha1));
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
    }

    /**
     * Calculate size and digests
     * @param is data input stream
     */
    public void calcHashes(InputStream is)
            throws DigiDocException
    {
        calcHashesAndWriteToStream(is, null);
    }

    /**
     * Calculate data file hash based on digest type and container type
     * @param digType digest type
     */
    private byte[] calcHashOfType(String digType)
            throws DigiDocException
    {
        byte[] dig = null;
        InputStream is = null;
        try {
            if(digType == null || !digType.equals(SignedDoc.SHA1_DIGEST_TYPE)) {
                throw new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM, "Invalid digest type: " + digType, null);
            }
            if(m_sigDoc.getFormat().equals(SignedDoc.FORMAT_SK_XML) ||
                    m_sigDoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)) {
                return getDigest();
            }
            MessageDigest sha = MessageDigest.getInstance(digType);
            byte[] data = new byte[2048];
            int nRead = 0, nTotal = 0;
            is = getBodyAsStream();
            do {
                nRead = is.read(data);
                if(nRead > 0) {
                    sha.update(data, 0, nRead);
                    nTotal += nRead;
                }
            } while(nRead > 0);
            dig = sha.digest();
            if(m_logger.isDebugEnabled())
                m_logger.debug("DF: " + m_id + " size: " + nTotal + " digest: " + digType + " = " + Base64Util.encode(dig));
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        } finally {
            try {
                if(is != null)
                    is.close();
            } catch(Exception ex) {
                m_logger.error("Error closing stream: " + ex);
            }
        }
        return dig;
    }

    /**
     * Set datafile cached content or cache file, calculate size and digest
     * @param is data input stream
     */
    public void setOrCacheBodyAndCalcHashes(InputStream is)
            throws DigiDocException
    {
        OutputStream os = null;
        try {
            m_fDfCache = createCacheFile();
            if(m_fDfCache != null)
                os = new FileOutputStream(m_fDfCache);
            else
                os = new ByteArrayOutputStream();
            calcHashesAndWriteToStream(is, os);
            if(m_fDfCache == null)
                m_body = ((ByteArrayOutputStream)os).toByteArray();
            if(m_logger.isDebugEnabled())
                m_logger.debug("DF: " + m_id + " size: " + m_size +
                        " cache: " + ((m_fDfCache != null) ? m_fDfCache.getAbsolutePath() : "MEMORY") +
                        " dig-sha1: " + Base64Util.encode(m_digestSha1));
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        } finally {
            try { if(os != null) os.close(); }
            catch(Exception ex) { m_logger.error("Error closing stream: " + ex); }
        }
    }

    /**
     * Accessor for body attribute.
     * Returns the body as a string. Takes in
     * account the initial codepage. usable
     * only for EMBEDDED type of documents or
     * if body is stored in Base64 then you have to be
     * sure that the converted data is textual and
     * can be returned as a String after decoding.
     * @return body as string
     */
    public String getBodyAsString()
            throws DigiDocException
    {
        String str = null;
        if(m_fDfCache != null) {
            try {
                byte[] data = SignedDoc.readFile(m_fDfCache);
                if(m_contentType.equals(CONTENT_EMBEDDED_BASE64))
                    str = ConvertUtils.data2str(Base64Util.decode(data), m_codepage);
            } catch(Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
            }
        } else {
            if(m_contentType.equals(CONTENT_EMBEDDED_BASE64))
                str = ConvertUtils.data2str(Base64Util.decode(m_body), m_codepage);
        }
        return str;
    }

    /**
     * Accessor for body attribute.
     * Returns the body as a byte array. If body contains
     * embedded base64 data then this is decoded first
     * and decoded actual payload data returned.
     * @return body as a byte array
     */
    public byte[] getBodyAsData()
            throws DigiDocException
    {
        byte[] data = null;
        if(m_fDfCache != null) {
            try {
                data = SignedDoc.readFile(m_fDfCache);
                if(m_contentType.equals(CONTENT_EMBEDDED_BASE64))
                    data = Base64Util.decode(data);
            } catch(Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
            }
        } else {
            if(m_contentType.equals(CONTENT_EMBEDDED_BASE64))
                data = Base64Util.decode(m_body);
        }
        return data;
    }

    public boolean hasAccessToDataFile()
    {
        if(m_fDfCache != null || m_body != null)
            return true;
        StringBuffer sbFil = new StringBuffer();
        File fT = new File(m_fileName);
        return fT.isFile() && fT.canRead();
    }

    /**
     * Accessor for body attribute.
     * Returns the body as an input stream. If body contains
     * embedded base64 data then this is decoded first
     * and decoded actual payload data returned.
     * @return body as a byte array
     */
    public InputStream getBodyAsStream()
            throws DigiDocException
    {
        InputStream strm = null;
        if(m_logger.isDebugEnabled())
            m_logger.debug("get body as stream f-cache: " + ((m_fDfCache != null) ? m_fDfCache.getAbsolutePath() : "NULL") +
                    " file: " + ((m_fileName != null) ? m_fileName : "NULL") + " content: " + m_contentType +
                    " body: " + ((m_body != null) ? m_body.length : 0) + " is-b64: " + m_bodyIsBase64);
        if(m_fDfCache != null || m_fileName != null) {
            try {
                if(m_contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    //strm = new iaik.utils.Base64InputStream(new FileInputStream(m_fDfCache));
                    if(m_fDfCache != null)
                        strm = new Base64InputStream(new FileInputStream(m_fDfCache));
                    else if(m_body != null) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug(" body: " + ((m_body != null) ? m_body.length : 0)  + " data: \n---\n" + new String(m_body) + "\n--\n");
                        strm = new Base64InputStream(new ByteArrayInputStream(m_body));
                    }
                }
                else if(m_contentType.equals(CONTENT_BINARY)) {
                    if(m_fDfCache != null)
                        strm = new FileInputStream(m_fDfCache);
                    else if(m_body != null)
                        strm = new ByteArrayInputStream(m_body);
                    else if(m_fileName != null)
                        strm = new FileInputStream(m_fileName);
                }
            } catch(Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
            }
        } else if(m_body != null) {

        }
        return strm;
    }

    /**
     * Checks if this DataFile object schould use a temp file
     * to store it's data because of memory cache size limitation
     * @return true if this object schould use temp file
     */
    public boolean schouldUseTempFile()
    {
        long lMaxDfCached = ConfigManager.instance().
                getLongProperty("DIGIDOC_MAX_DATAFILE_CACHED", Long.MAX_VALUE);
        return (lMaxDfCached > 0 && (m_size == 0 || (m_size > lMaxDfCached && (m_contentType == null || m_contentType.equals(CONTENT_EMBEDDED_BASE64)))));
    }

    /**
     * Helper method to enable temporary cache file for this DataFile
     * @return new temporary file object
     * @throws IOException
     */
    public File createCacheFile()
            throws IOException
    {
        //m_fDfCache = null;
        if((m_fDfCache == null) && schouldUseTempFile()) {
            File fCacheDir = new File(ConfigManager.instance().
                    getStringProperty("DIGIDOC_DF_CACHE_DIR", System.getProperty("java.io.tmpdir")));
            String dfId = new Long(System.currentTimeMillis()).toString();
            m_fDfCache = File.createTempFile(dfId, ".df", fCacheDir);
        }
        return m_fDfCache;
    }

    public void setCacheFile(File d)
    {
        m_fDfCache = d;
    }

    /**
     * Helper method to store body in file if it exceeds the
     * memory cache limit
     * @throws IOException
     */
    private void storeInTempFile()
            throws IOException
    {
        File f = createCacheFile();
        if(f != null) {
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(m_body);
            fos.close();
            // remove memory cache if stored in file
            m_body = null;
        }
    }

    /**
     * Use this method to assign data directly to body.
     * If you do this then the input file will not be read.
     * This also sets the initial size and codepage for you
     * @param data new value for body attribute
     * @deprecated embedded xml no longer supported
     */
    public void setBody(byte[] data, String codepage)
            throws DigiDocException
    {
        try {
            m_body = data;
            m_codepage = codepage;
            m_size = m_body.length;
            // check if data must be stored in file instead
            storeInTempFile();
        } catch(IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    /**
     * Use this method to assign data directly to body.
     * Input data is an XML subtree
     * @param xml xml subtree containing input data
     * @param codepage input data's original codepage
     * @deprecated embedded xml no longer supported
     */
    public void setBody(Node xml)
            throws DigiDocException
    {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            TransformerFactory tFactory = TransformerFactory.newInstance();
            Transformer transformer = tFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            DOMSource source = new DOMSource(xml);
            StreamResult result = new StreamResult(bos);
            transformer.transform(source, result);
            m_body = bos.toByteArray();
            // DOM library always outputs in UTF-8
            m_codepage = "UTF-8";
            m_size = m_body.length;
            // check if data must be stored in file instead
            storeInTempFile();
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
    }

    /**
     * Accessor for initialCodepage attribute.
     * @return value of initialCodepage attribute
     * @deprecated embedded xml no longer supported
     */
    public String getInitialCodepage() {
        return m_codepage;
    }

    /**
     * Mutator for initialCodepage attribute.
     * If you use setBody() or assign data from a file
     * which is not in UTF-8 and then use CONTENT_EMBEDDED
     * then you must use this method to tell the library
     * in which codepage your data is so that we
     * can convert it to UTF-8.
     * @param data new value for initialCodepage attribute
     * @deprecated embedded xml no longer supported
     */
    public void setInitialCodepage(String data)
    {
        m_codepage = data;
    }

    /**
     * Accessor for contentType attribute
     * @return value of contentType attribute
     */
    public String getContentType() {
        return m_contentType;
    }

    /**
     * Mutator for contentType attribute
     * @param str new value for contentType attribute
     * @throws DigiDocException for validation errors
     */
    public void setContentType(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateContentType(str);
        if(ex != null)
            throw ex;
        m_contentType = str;
    }

    /**
     * Helper method to validate a content type
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateContentType(String str)
    {
        DigiDocException ex = null;
        boolean bUseHashcode = ConfigManager.instance().getBooleanProperty("DATAFILE_HASHCODE_MODE", false);
        if(m_sigDoc != null &&
                (str == null ||
                        (!str.equals(CONTENT_EMBEDDED_BASE64) && !str.equals(CONTENT_HASHCODE)) ||
                        (str.equals(CONTENT_HASHCODE) && !bUseHashcode)))
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_CONTENT_TYPE,
                    "Currently supports only content types EMBEDDED_BASE64 for DDOC format", null);
        return ex;
    }

    /**
     * Accessor for fileName attribute
     * @return value of fileName attribute
     */
    public String getFileName() {
        return m_fileName;
    }

    /**
     * Mutator for fileName attribute
     * @param str new value for fileName attribute
     * @throws DigiDocException for validation errors
     */
    public void setFileName(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateFileName(str);
        if(ex != null)
            throw ex;
        m_fileName = str;
    }

    /**
     * Helper method to validate a file name
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateFileName(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_FILE_NAME,
                    "Filename is a required attribute", null);
        return ex;
    }

    /**
     * Accessor for id attribute
     * @return value of id attribute
     */
    public String getId() {
        return m_id;
    }

    /**
     * Mutator for id attribute
     * @param str new value for id attribute
     * @throws DigiDocException for validation errors
     */
    public void setId(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateId(str, false);
        if(ex != null)
            throw ex;
        m_id = str;
    }

    /**
     * Helper method to validate an id
     * @param str input data
     * @param bStrong flag that specifies if Id atribute value is to
     * be rigorously checked (according to digidoc format) or only
     * as required by XML-DSIG
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str, boolean bStrong)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_ID,
                    "Id is a required attribute", null);
        if(str != null && bStrong &&
                m_sigDoc.getFormat() != null &&
                (str.charAt(0) != 'D' || (!Character.isDigit(str.charAt(1)) && str.charAt(1) != 'O')))
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_ID,
                    "Id attribute value has to be in form D<number> or DO", null);
        return ex;
    }

    /**
     * Accessor for mimeType attribute
     * @return value of mimeType attribute
     */
    public String getMimeType() {
        return m_mimeType;
    }

    /**
     * Mutator for mimeType attribute
     * @param str new value for mimeType attribute
     * @throws DigiDocException for validation errors
     */
    public void setMimeType(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateMimeType(str);
        if(ex != null)
            throw ex;
        m_mimeType = str;
    }

    /**
     * Helper method to validate a mimeType
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateMimeType(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_MIME_TYPE,
                    "MimeType is a required attribute", null);
        return ex;
    }

    /**
     * Accessor for size attribute
     * @return value of size attribute
     */
    public long getSize() {
        return m_size;
    }

    /**
     * Mutator for size attribute
     * @param l new value for size attribute
     * @throws DigiDocException for validation errors
     */
    public void setSize(long l)
            throws DigiDocException
    {
        DigiDocException ex = validateSize(l);
        if(ex != null)
            throw ex;
        m_size = l;
    }

    /**
     * Helper method to validate a mimeType
     * @param l input data
     * @return exception or null for ok
     */
    private DigiDocException validateSize(long l)
    {
        DigiDocException ex = null;
        if(l < 0)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_SIZE,
                    "Size must be greater or equal to zero", null);
        return ex;
    }

    /**
     * Accessor for digestType attribute
     * @return value of digestType attribute
     */
    public String getDigestType() {
        if(m_sigDoc != null && m_sigDoc.countSignatures() > 0) {
            Reference ref = m_sigDoc.getSignature(0).getSignedInfo().getReferenceForDataFile(this);
            if(ref != null)
                return ref.getDigestAlgorithm();
            else
                return SignedDoc.SHA1_DIGEST_TYPE;
        }
        return null;
    }


    /**
     * Helper method to validate a digestType
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestType(String str)
    {
        DigiDocException ex = null;
        if(str != null && !str.equals("sha1") && !str.equals(SignedDoc.SHA1_DIGEST_TYPE))
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_DIGEST_TYPE,
                    "The only supported digest types are sha1", null);
        return ex;
    }

    /**
     * Accessor for digestValue attribute
     * @param desired digest type
     * @return value of digestValue attribute
     */
    public byte[] getDigestValueOfType(String digType)
            throws DigiDocException
    {
        if(digType != null) {
            if(digType.equals(SignedDoc.SHA1_DIGEST_TYPE) || digType.equals("sha1")) {
                if(m_digestSha1 == null && m_origDigestValue == null)
                    m_digestSha1 = m_origDigestValue = calcHashOfType(SignedDoc.SHA1_DIGEST_TYPE);
                return ((m_digestSha1 != null) ? m_digestSha1 : m_origDigestValue);
            }
        }
        return m_digestSha1;
    }

    /**
     * Mutator for digestValue attribute
     * @param data new value for digestValue attribute
     * @throws DigiDocException for validation errors
     */
    public void setDigestValue(byte[] data)
            throws DigiDocException
    {
        DigiDocException ex = validateDigestValue(data);
        if(ex != null)
            throw ex;
        if(data.length == SignedDoc.SHA1_DIGEST_LENGTH)
            m_digestSha1 = data;
    }

    /**
     * Accessor for digest attribute
     * @return value of digest attribute
     */
    public byte[] getDigest()
            throws DigiDocException
    {
        if(m_origDigestValue == null)
            calculateFileSizeAndDigest(null);
        return m_origDigestValue;
    }

    /**
     * Mutator for digest attribute
     * @param data new value for digest attribute
     * @throws DigiDocException for validation errors
     */
    public void setDigest(byte[] data)
            throws DigiDocException
    {
        DigiDocException ex = validateDigestValue(data);
        if(ex != null)
            throw ex;
        m_origDigestValue = data;
    }

    /**
     * Accessor for alternate digest attribute
     * @return value of digest attribute
     */
    public byte[] getAltDigest()
    {
        return m_digestAlt;
    }

    /**
     * Mutator for alternate digest attribute
     * @param b new value for alternate digest attribute
     * @throws DigiDocException for validation errors
     */
    public void setAltDigest(byte[] b)
    {
        m_digestAlt = b;
    }


    /**
     * Helper method to validate a digestValue
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestValue(byte[] data)
    {
        DigiDocException ex = null;
        if(data != null && data.length != SignedDoc.SHA1_DIGEST_LENGTH)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_DIGEST_VALUE,
                    "SHA1 digest value must be 20 bytes - is: " + data.length, null);
        return ex;
    }

    /**
     * Returns the count of attributes
     * @return count of attributes
     */
    public int countAttributes()
    {
        return ((m_attributes == null) ? 0 : m_attributes.size());
    }

    /**
     * Adds a new DataFileAttribute object
     * @param attr DataFileAttribute object to add
     */
    public void addAttribute(DataFileAttribute attr)
    {
        if(m_attributes == null)
            m_attributes = new ArrayList();
        m_attributes.add(attr);
    }

    /**
     * Returns the desired DataFileAttribute object
     * @param idx index of the DataFileAttribute object
     * @return desired DataFileAttribute object
     */
    public DataFileAttribute getAttribute(int idx) {
        return (DataFileAttribute)m_attributes.get(idx);
    }

    /**
     * Accessor for comment attribute
     * @return value of comment attribute
     */
    public String getComment()
    {
        return m_comment;
    }

    /**
     * Mutator for comment attribute
     * @param s new value for comment attribute
     */
    public void setComment(String s)
    {
        m_comment = s;
    }

    /**
     * Helper method to validate the whole
     * DataFile object
     * @param bStrong flag that specifies if Id atribute value is to
     * be rigorously checked (according to digidoc format) or only
     * as required by XML-DSIG
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate(boolean bStrong)
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateContentType(m_contentType);
        if(ex != null)
            errs.add(ex);
        ex = validateFileName(m_fileName);
        if(ex != null)
            errs.add(ex);
        ex = validateId(m_id, bStrong);
        if(ex != null)
            errs.add(ex);
        ex = validateMimeType(m_mimeType);
        if(ex != null)
            errs.add(ex);
        ex = validateSize(m_size);
        if(ex != null)
            errs.add(ex);
        for(int i = 0; i < countAttributes(); i++) {
            DataFileAttribute attr = getAttribute(i);
            ArrayList e = attr.validate();
            if(!e.isEmpty())
                errs.addAll(e);
        }
        return errs;
    }

    /**
     * Helper method to canonicalize a piece of xml
     * @param xml data to be canonicalized
     * @return canonicalized xml
     */
    private byte[] canonicalizeXml(byte[] data) {
        try {
            CanonicalizationFactory canFac = ConfigManager.
                    instance().getCanonicalizationFactory();
            byte[] tmp = canFac.canonicalize(data,
                    SignedDoc.CANONICALIZATION_METHOD_20010315);
            return tmp;
        } catch(Exception ex) {
            m_logger.error("Canonicalizing exception: " + ex);
        }
        return null;
    }

    /**
     * Helper method for using an optimization for base64 data's
     * conversion and digest calculation. We use data blockwise to
     * conserve memory
     * @param os output stream to write data
     * @param digest existing sha1 digest to be updated
     * @param b64leftover leftover base64 data from previous block
     * @param b64left leftover data length
     * @param data new binary data
     * @param dLen number of used bytes in data
     * @param bLastBlock flag last block
     * @return length of leftover bytes from this block
     * @throws DigiDocException
     */
    private int calculateAndWriteBase64Block(OutputStream os, MessageDigest digest,
                                             byte[] b64leftover, int b64left, byte[] data, int dLen, boolean bLastBlock)
            throws DigiDocException
    {
        byte[] b64input = null;
        int b64Used, nLeft = 0, nInLen = 0;
        StringBuffer b64data = new StringBuffer();

        if(m_logger.isDebugEnabled())
            m_logger.debug("os: " + ((os != null) ? "Y" :"N") +
                    " b64left: " + b64left + " input: " + dLen + " last: " + (bLastBlock ? "Y" : "N"));
        try {
            // use data from the last block
            if(b64left > 0) {
                if(dLen > 0) {
                    b64input = new byte[dLen + b64left];
                    nInLen = b64input.length;
                    System.arraycopy(b64leftover, 0, b64input, 0, b64left);
                    System.arraycopy(data, 0, b64input, b64left, dLen);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("use left: " + b64left + " from 0 and add " + dLen);
                } else {
                    b64input = b64leftover;
                    nInLen = b64left;
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("use left: " + b64left + " with no new data");
                }
            } else {
                b64input = data;
                nInLen = dLen;
                if(m_logger.isDebugEnabled())
                    m_logger.debug("use: " + nInLen + " from 0");
            }
            // encode full rows
            b64Used = Base64Util.encodeToBlock(b64input, nInLen, b64data, bLastBlock);
            nLeft = nInLen - b64Used;
            // use the encoded data
            byte[] encdata = b64data.toString().getBytes();
            if(os != null)
                os.write(encdata);
            digest.update(encdata);
            // now copy not encoded data back to buffer
            if(m_logger.isDebugEnabled())
                m_logger.debug("Leaving: " + nLeft + " of: " + b64input.length);
            if(nLeft > 0)
                System.arraycopy(b64input, b64input.length - nLeft, b64leftover, 0, nLeft);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        if(m_logger.isDebugEnabled())
            m_logger.debug("left: " + nLeft + " bytes for the next run");
        return nLeft;
    }

    /**
     * Calculates the DataFiles size and digest
     * Since it calculates the digest of the external file
     * then this is only useful for detatched files
     * @throws DigiDocException for all errors
     */
    public void calculateFileSizeAndDigest(OutputStream os)
            throws DigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("calculateFileSizeAndDigest(" + getId() + ") body: " +
                    ((m_body != null) ? "OK" : "NULL") + " base64: " + m_bodyIsBase64 +
                    " DF cache: " + ((m_fDfCache != null) ? m_fDfCache.getAbsolutePath() : "NULL"));
        FileInputStream fis = null;
        if(m_contentType.equals(CONTENT_BINARY)) {
            InputStream is = null;
            try {
                if(getDfCacheFile() != null)
                    is = getBodyAsStream();
                else if(is == null && m_body != null)
                    is = new java.io.ByteArrayInputStream(m_body);
                else if(is == null && m_fileName != null)
                    is = new java.io.FileInputStream(m_fileName);
                if(is != null)
                    calcHashes(is);
            } catch(java.io.FileNotFoundException ex) {
                throw new DigiDocException(DigiDocException.ERR_READ_FILE, "Cannot read file: " + m_fileName, null);
            } finally {
                try {
                    if(is != null)
                        is.close();
                } catch(Exception ex) {
                    m_logger.error("Error closing stream: " + ex);
                }
            }
            return;
        }

        MessageDigest sha = null;
        boolean bUse64ByteLines = true;
        String use64Flag = ConfigManager.instance().getProperty("DATAFILE_USE_64BYTE_LINES");
        if(use64Flag != null && use64Flag.equalsIgnoreCase("FALSE"))
            bUse64ByteLines = false;
        try {
            sha = MessageDigest.getInstance("SHA-1"); // TODO: fix digest type
            // if DataFile's digest has already been initialized
            // and body in memory, e.g. has been read from digidoc
            // then write directly to output stream and don't calculate again
            if(m_origDigestValue != null && m_body != null && os != null) {
                os.write(xmlHeader());
                if(m_logger.isDebugEnabled())
                    m_logger.debug("write df header1: " + xmlHeader());
                os.write(m_body);
                os.write(xmlTrailer());
                return;
            }
            String longFileName = m_fileName;
            File fIn = new File(m_fileName);
            m_fileName = fIn.getName();
            if(fIn.canRead() && m_fDfCache == null) {
                fis = new FileInputStream(longFileName);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Read file: " + longFileName);
            }
            else if(m_fDfCache != null) {
                fis = new FileInputStream(m_fDfCache);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Read cache: " + m_fDfCache);
            }
            byte[] tmp1=null,tmp2=null,tmp3=null;
            ByteArrayOutputStream sbDig = new ByteArrayOutputStream();
            sbDig.write(xmlHeader());
            // add trailer and canonicalize
            tmp3 = xmlTrailer();
            sbDig.write(tmp3);
            tmp1 = canonicalizeXml(sbDig.toByteArray());
            // now remove the end tag again and calculate digest of the start tag only
            if(tmp1 != null) {
                tmp2 = new byte[tmp1.length - tmp3.length];
                System.arraycopy(tmp1, 0, tmp2, 0, tmp2.length);
                sha.update(tmp2);
                if(os != null)
                    os.write(xmlHeader());
            }
            // reset the collecting buffer and other temp buffers
            sbDig = new ByteArrayOutputStream();
            tmp1 = tmp2 = tmp3 = null;
            // content must be read from file
            if(m_body == null) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Reading input file: " + ((fIn.canRead() && m_fDfCache == null) ? longFileName : ((m_fDfCache != null) ? m_fDfCache.getAbsolutePath() : "no-cache")));
                byte[] buf = new byte[block_size];
                byte[] b64leftover = null;
                int fRead = 0, b64left = 0;
                ByteArrayOutputStream content = null;
                if(m_contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    // optimization for 64 char base64 lines
                    // convert to base64 online at a time to conserve memory
                    // VS: DF temp file base64 decoding fix
                    if(m_fDfCache == null) {
                        if(bUse64ByteLines)
                            b64leftover = new byte[65];
                        else
                            content = new ByteArrayOutputStream();
                    }
                }
                while((fRead = fis.read(buf)) > 0 || b64left > 0) { // read input file
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("read: " + fRead + " bytes of input data");
                    if(m_contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                        // VS: DF temp file base64 decoding fix
                        if(m_fDfCache != null) {
                            if(os != null)
                                os.write(buf, 0, fRead);
                            sha.update(buf, 0, fRead);
                        } else {
                            if(bUse64ByteLines) { // 1 line base64 optimization
                                b64left = calculateAndWriteBase64Block(os, sha, b64leftover,
                                        b64left, buf, fRead, fRead < block_size);
                            } else { // no optimization
                                content.write(buf, 0, fRead);
                            }
                        }
                    } else {
                        if(fRead < buf.length) {
                            tmp2= new byte[fRead];
                            System.arraycopy(buf, 0, tmp2, 0, fRead);
                            tmp1 = ConvertUtils.data2utf8(tmp2, m_codepage);
                        }
                        else
                            tmp1 = ConvertUtils.data2utf8(buf, m_codepage);
                        sbDig.write(tmp1);
                    }
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("End using block: " + fRead + " in: " + ((fis != null) ? fis.available() : 0));
                } // end reading input file
                if(m_contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    // VS: DF temp file base64 decoding fix
                    if(!bUse64ByteLines && m_fDfCache == null)
                        sbDig.write(Base64Util.encode(content.toByteArray(), 0).getBytes());
                    content = null;
                }
                if(m_logger.isDebugEnabled())
                    m_logger.debug("End reading content");
            } else { // content allready in memeory
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Using mem content, len: " + ((m_body != null) ? m_body.length : 0) + " b64: " + m_bodyIsBase64);
                if(m_body != null) {
                    if(bUse64ByteLines && m_contentType.equals(CONTENT_EMBEDDED_BASE64) && !m_bodyIsBase64) {
                        calculateAndWriteBase64Block(os, sha, null, 0, m_body, m_body.length, true);
                        m_body = Base64Util.encode(m_body).getBytes();
                        //sbDig.write(m_body); // this code block not used any more ?
                    } else {
                        if(m_contentType.equals(CONTENT_EMBEDDED_BASE64) && !m_bodyIsBase64) {
                            tmp1 = Base64Util.encode(m_body).getBytes();
                        } else if(m_contentType.equals(CONTENT_EMBEDDED_BASE64) && m_bodyIsBase64) {
                            tmp1 = ConvertUtils.data2utf8(m_body, m_codepage);
                        } else
                            tmp1 = ConvertUtils.data2utf8(m_body, m_codepage);
                        sbDig.write(tmp1);
                    }
                }
            }
            tmp1 = null;
            // don't need to canonicalize base64 content !
            if(m_contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                // VS: DF temp file base64 decoding fix
                if(!bUse64ByteLines && m_fDfCache == null) {
                    tmp2 = sbDig.toByteArray();
                    if(tmp2 != null && tmp2.length > 0) {
                        sha.update(tmp2);
                        if(os != null)
                            os.write(tmp2);
                    }
                } else if(m_body != null && sbDig.size() > 0) {
                    tmp2 = sbDig.toByteArray();
                    if(tmp2 != null && tmp2.length > 0) {
                        sha.update(tmp2);
                        if(os != null)
                            os.write(tmp2);
                    }
                }
            } else {
                // canonicalize body
                tmp2 = sbDig.toByteArray();
                if(tmp2 != null && tmp2.length > 0) {
                    if(tmp2[0] == '<')
                        tmp2 = canonicalizeXml(tmp2);
                    if(tmp2 != null && tmp2.length > 0) {
                        sha.update(tmp2);  // crash
                        if(os != null)
                            os.write(tmp2);
                    }
                }
            }
            tmp2 = null;
            sbDig = null;
            // trailer
            tmp1 = xmlTrailer();
            sha.update(tmp1);
            if(os != null)
                os.write(tmp1);
            // now calculate the digest
            byte[] digest = sha.digest();
            setDigest(digest);
            if(m_logger.isDebugEnabled())
                m_logger.debug("DataFile: \'" + getId() + "\' length: " +
                        getSize() + " digest: " + Base64Util.encode(digest));
            m_fileName = longFileName;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        } finally {
            try {
                if(fis != null)
                    fis.close();
            } catch(Exception ex) {
                m_logger.error("Error closing file: " + ex);
            }
        }
    }


    /**
     * Writes the DataFile to an outout file
     * @param fos output stream
     * @throws DigiDocException for all errors
     */
    public void writeToFile(OutputStream fos)
            throws DigiDocException
    {
        // for detatched files just read them in
        // calculate digests and store a reference to them
        try {
            calculateFileSizeAndDigest(fos);
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
    }


    /**
     * Helper method to create the xml header
     * @return xml header
     */
    private byte[] xmlHeader()
            throws DigiDocException
    {
        StringBuffer sb = new StringBuffer("<DataFile");
        if(m_codepage != null && !m_codepage.equals("UTF-8")) {
            sb.append(" Codepage=\"");
            sb.append(m_codepage);
            sb.append("\"");
        }
        sb.append(" ContentType=\"");
        sb.append(m_contentType);
        sb.append("\" Filename=\"");
        // we write only file name not path to file
        String fileName = new File(m_fileName).getName();
        if(m_logger.isDebugEnabled())
            m_logger.debug("DF fname: " + ConvertUtils.escapeXmlSymbols(fileName));
        sb.append(ConvertUtils.escapeXmlSymbols(fileName));
        sb.append("\" Id=\"");
        sb.append(m_id);
        sb.append("\" MimeType=\"");
        sb.append(m_mimeType);
        sb.append("\" Size=\"");
        sb.append(new Long(m_size).toString());
        sb.append("\"");
        if(m_digestSha1 != null && getDigestType() != null) {
            sb.append(" DigestType=\"");
            if ("SHA-1".equalsIgnoreCase(getDigestType())) {
                sb.append(DIGEST_TYPE_SHA1);
            } else {
                sb.append(getDigestType());
            }
            sb.append("\" DigestValue=\"");
            sb.append(Base64Util.encode(m_digestSha1, 0));
            sb.append("\"");
        }
        for(int i = 0; i < countAttributes(); i++) {
            DataFileAttribute attr = getAttribute(i);
            sb.append(" ");
            sb.append(attr.toXML());
        }
        // namespace
        if(m_sigDoc != null &&
                m_sigDoc.getVersion().equals(SignedDoc.VERSION_1_3)) {
            sb.append(" xmlns=\"");
            sb.append(SignedDoc.xmlns_digidoc13);
            sb.append("\"");
        }
        sb.append(">");
        return ConvertUtils.str2data(sb.toString(), "UTF-8");
    }

    /**
     * Helper method to create the xml trailer
     * @return xml trailer
     */
    private byte[] xmlTrailer()
            throws DigiDocException
    {
        return ConvertUtils.str2data("</DataFile>", "UTF-8");
    }

    /**
     * Converts the DataFile to XML form
     * @return XML representation of DataFile
     */
    public byte[] toXML()
            throws DigiDocException
    {
        ByteArrayOutputStream sb = new ByteArrayOutputStream();
        try {
            sb.write(xmlHeader());
            if(m_body != null) {
                //if(m_contentType.equals(CONTENT_EMBEDDED_BASE64))
                //    sb.write(Base64Util.encode(m_body).getBytes());
                if(m_contentType.equals(CONTENT_EMBEDDED_BASE64))
                    sb.write(m_body);
            }
            sb.write(xmlTrailer());
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_ENCODING);
        }
        return sb.toByteArray();
    }

    /**
     * Returns the stringified form of DataFile
     * @return DataFile string representation
     */
    public String toString()
    {
        String str = null;
        try {
            str = new String(toXML(), "UTF-8");
        } catch(Exception ex) {}
        return str;
    }


}
