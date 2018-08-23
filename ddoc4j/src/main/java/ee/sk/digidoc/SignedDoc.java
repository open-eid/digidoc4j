package ee.sk.digidoc;

import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.DigiDocVerifyFactory;
import ee.sk.digidoc.factory.DigiDocXmlGenFactory;
import ee.sk.utils.ConfigManager;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;

/**
 * Represents an instance of signed doc
 * in DIGIDOC format. Contains one or more
 * DataFile -s and zero or more Signature -s.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignedDoc implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** digidoc format */
    private String m_format;
    /** format version */
    private String m_version;
    /** DataFile objects */
    private ArrayList m_dataFiles;
    /** Signature objects */
    private ArrayList m_signatures;
    /** bdoc manifest.xml file */
    private Manifest m_manifest;
    /** bdoc mime type */
    private String m_mimeType;
    /** xml-dsig namespace preifx */
    private String m_nsXmlDsig;
    /** xades namespace prefix */
    private String m_nsXades;
    /** asic namespace prefix */
    private String m_nsAsic;
    /** signature default profile */
    private String m_profile;
    /** container comment (bdoc2 lib ver and name. Maintaned by manifest file) */
    private String m_comment;
    /** hashtable of signature names and formats used during loading */
    private Hashtable m_sigFormats;
    private long m_size;
    /** original container path */
    private String m_path;
    /** original container filename without path */
    private String m_file;

    private static Logger m_logger = LoggerFactory.getLogger(SignedDoc.class);
    /** the only supported formats are SK-XML and DIGIDOC-XML */
    public static final String FORMAT_SK_XML = "SK-XML";
    public static final String FORMAT_DIGIDOC_XML = "DIGIDOC-XML";
    /**BDOC*/
    public static final String FORMAT_BDOC = "BDOC";
    /**application/vnd.bdoc*/
    public static final String FORMAT_BDOC_MIME = "application/vnd.bdoc";
    /** supported versions are 1.0 and 1.1 */
    public static final String VERSION_1_0 = "1.0";
    public static final String VERSION_1_1 = "1.1";
    public static final String VERSION_1_2 = "1.2";
    public static final String VERSION_1_3 = "1.3";
    /** bdoc versions are 1.0, 1.1 and 2.1 */
    public static final String BDOC_VERSION_1_0 = "1.0";
    public static final String BDOC_VERSION_1_1 = "1.1";
    public static final String BDOC_VERSION_2_1 = "2.1";
    /** bdoc profiles are - BES, T, C-L, TM, TS, TM-A, TS-A */
    public static final String BDOC_PROFILE_BES = "BES";
    public static final String BDOC_PROFILE_T = "T";
    public static final String BDOC_PROFILE_CL = "C-L";
    public static final String BDOC_PROFILE_TM = "TM";
    public static final String BDOC_PROFILE_TS = "TS";
    public static final String BDOC_PROFILE_TMA = "TM-A";
    public static final String BDOC_PROFILE_TSA = "TS-A";

    /** the only supported algorithm for ddoc is SHA1 */
    public static final String SHA1_DIGEST_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#sha1";
    public static final String SHA1_DIGEST_TYPE="SHA-1";
    public static final String SHA1_DIGEST_TYPE_BAD="SHA-1-00";
    /** the only supported algorithm for bdoc is SHA256 */
    public static final String SHA256_DIGEST_ALGORITHM_1 = "http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String SHA256_DIGEST_ALGORITHM_2 = "http://www.w3.org/2001/04/xmldsig-more#sha256";
    public static final String SHA256_DIGEST_TYPE="SHA-256";
    /** algorithms for sha 224 **/
    public static final String SHA224_DIGEST_TYPE="SHA-224";
    public static final String SHA224_DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#sha224";
    /** algorithms for sha 384 **/
    public static final String SHA384_DIGEST_TYPE="SHA-384";
    public static final String SHA384_DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    /** sha-512 digest type */
    public static final String SHA512_DIGEST_TYPE="SHA-512";
    public static final String SHA512_DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha512"; //"http://www.w3.org/2001/04/xmldsig-more#sha512";

    /** SHA1 digest data is allways 20 bytes */
    public static final int SHA1_DIGEST_LENGTH = 20;
    /** SHA224 digest data is allways 28 bytes */
    public static final int SHA224_DIGEST_LENGTH = 28;
    /** SHA256 digest data is allways 32 bytes */
    public static final int SHA256_DIGEST_LENGTH = 32;
    /** SHA512 digest data is allways 64 bytes */
    public static final int SHA512_DIGEST_LENGTH = 64;
    /** the only supported canonicalization method is 20010315 */
    public static final String CANONICALIZATION_METHOD_20010315 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /** canonical xml 1.1 */
    public static final String CANONICALIZATION_METHOD_1_1 = "http://www.w3.org/2006/12/xml-c14n11";
    public static final String CANONICALIZATION_METHOD_2010_10_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String TRANSFORM_20001026 = "http://www.w3.org/TR/2000/CR-xml-c14n-20001026";
    /** the only supported signature method is RSA-SHA1 */
    public static final String RSA_SHA1_SIGNATURE_METHOD = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    public static final String RSA_SHA224_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
    public static final String RSA_SHA256_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String RSA_SHA384_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    public static final String RSA_SHA512_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    /** elliptic curve algorithms */
    public static final String ECDSA_SHA1_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    public static final String ECDSA_SHA224_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
    public static final String ECDSA_SHA256_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    public static final String ECDSA_SHA384_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    public static final String ECDSA_SHA512_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    /** the only supported transform is digidoc detatched transform */
    public static final String DIGIDOC_DETATCHED_TRANSFORM = "http://www.sk.ee/2002/10/digidoc#detatched-document-signature";
    public static final String ENVELOPED_TRANSFORM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    public static final String SIGNEDPROPERTIES_TYPE="http://uri.etsi.org/01903#SignedProperties";
    /** XML-DSIG namespace */
    public static String xmlns_xmldsig = "http://www.w3.org/2000/09/xmldsig#";
    /** ETSI namespace */
    public static String xmlns_etsi = "http://uri.etsi.org/01903/v1.1.1#";
    /** DigiDoc namespace */
    public static String xmlns_digidoc13 = "http://www.sk.ee/DigiDoc/v1.3.0#";
    /** asic namespace */
    public static String xmlns_asic = "http://uri.etsi.org/02918/v1.2.1#";

    /** program & library name */
    public static final String LIB_NAME = Version.LIB_NAME;
    /** program & library version */
    public static final String LIB_VERSION = Version.LIB_VERSION;
    /** Xades namespace */
    public static String xmlns_xades_123 = "http://uri.etsi.org/01903/v1.3.2#";
    /** program & library name */
    public static final String  SIG_FILE_NAME = "META-INF/signature";
    public static final String  SIG_FILE_NAME_20 = "META-INF/signatures";
    public static final String  MIMET_FILE_NAME = "mimetype";
    public static final String  MIMET_FILE_CONTENT_10 = "application/vnd.bdoc-1.0";
    public static final String  MIMET_FILE_CONTENT_11 = "application/vnd.bdoc-1.1";
    public static final String  MIMET_FILE_CONTENT_20 = "application/vnd.etsi.asic-e+zip";
    public static final String  MANIF_DIR_META_INF = "META-INF";
    public static final String  MANIF_FILE_NAME = "META-INF/manifest.xml";
    public static final String  MIME_SIGNATURE_BDOC_ = "signature/bdoc-";

    /**
     * Creates new SignedDoc
     * Initializes everything to null
     */
    public SignedDoc() {
        m_format = null;
        m_version = null;
        m_dataFiles = null;
        m_signatures = null;
        m_manifest = null;
        m_mimeType = null;
        m_nsXmlDsig = null;
        m_nsXades = null;
        m_nsAsic = null;
        m_file = null;
        m_path = null;
        m_comment = null;
    }

    /**
     * Creates new SignedDoc
     * @param format file format name
     * @param version file version number
     * @throws DigiDocException for validation errors
     */
    public SignedDoc(String format, String version)
            throws DigiDocException
    {
        setFormatAndVersion(format, version);
        m_dataFiles = null;
        m_signatures = null;
        m_manifest = null;
        m_mimeType = null;
        m_nsXmlDsig = null;
        m_nsXades = null;
        m_comment = null;
        if(format.equals(SignedDoc.FORMAT_BDOC)) {
            m_manifest = new Manifest();
            ManifestFileEntry fe = new ManifestFileEntry(getManifestEntry(version), "/");
            m_manifest.addFileEntry(fe);
            setDefaultNsPref(SignedDoc.FORMAT_BDOC);
        }
    }

    public void setDefaultNsPref(String format)
    {
        if(format.equals(SignedDoc.FORMAT_BDOC)) {
            m_nsXmlDsig = "ds";
            m_nsXades = "xades";
            m_nsAsic = "asic";
        }
        if(format.equals(SignedDoc.FORMAT_DIGIDOC_XML) || format.equals(SignedDoc.FORMAT_SK_XML)) {
            m_nsXmlDsig = null;
            m_nsXades = null;
            m_nsAsic = null;
        }
    }

    private String getManifestEntry(String ver)
    {
        if(ver.equals(BDOC_VERSION_1_0))
            return Manifest.MANIFEST_BDOC_MIME_1_0;
        else if(ver.equals(BDOC_VERSION_1_1))
            return Manifest.MANIFEST_BDOC_MIME_1_1;
        else
            return Manifest.MANIFEST_BDOC_MIME_2_0;
    }

    /**
     * Finds Manifest file-netry by path
     * @param fullPath file path in bdoc
     * @return file-netry if found
     */
    public ManifestFileEntry findManifestEntryByPath(String fullPath)
    {
        return m_manifest.findFileEntryByPath(fullPath);
    }

    /**
     * Accessor for format attribute
     * @return value of format attribute
     */
    public String getFormat() {
        return m_format;
    }

    /**
     * Mutator for format attribute
     * @param str new value for format attribute
     * @throws DigiDocException for validation errors
     */
    public void setFormat(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateFormat(str);
        if(ex != null)
            throw ex;
        m_format = str;
    }

    /**
     * Accessor for all data-files atribute
     * @return all data-files
     */
    public ArrayList getDataFiles() { return m_dataFiles; }

    /**
     * Mutator for all data-files atribute
     * @param l list of data-files
     */
    public void setDataFiles(ArrayList l) { m_dataFiles = l; }

    /**
     * Accessor for all signatures atribute
     * @return all signatures
     */
    public ArrayList getSignatures() { return m_signatures; }

    /**
     * Accessor for size atribute
     * @return size in bytes
     */
    public long getSize() { return m_size; }

    /**
     * Mutator for size atribute
     * @param size in bytes
     */
    public void setSize(long l) { m_size = l; }

    /**
     * Accessor for file atribute
     * @return original container filename without path
     */
    public String getFile() { return m_file; }

    /**
     * Mutator for file atribute
     * @param fname original filename without path
     */
    public void setFile(String fname) { m_file = fname; }

    /**
     * Accessor for path atribute
     * @return original file path without filename
     */
    public String getPath() { return m_path; }

    /**
     * Mutator for size atribute
     * @param p original container path without filename
     */
    public void setPath(String p) { m_path = p; }

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
     * Registers a new signature format
     * @param sigId signature id
     * @param profile format/profile
     */
    public void addSignatureProfile(String sigId, String profile)
    {
        if(m_sigFormats == null)
            m_sigFormats = new Hashtable();
        if(m_logger.isDebugEnabled())
            m_logger.debug("Register signature: " + sigId + " profile: " + profile);
        m_sigFormats.put(sigId, profile);
    }

    /**
     * Returns signature profile
     * @param sigId signature id
     * @return profile
     */
    public String findSignatureProfile(String sigId)
    {
        return ((m_sigFormats != null && sigId != null) ? (String)m_sigFormats.get(sigId) : null);
    }

    /**
     * Accessor for xml-dsig ns prefix attribute
     * @return value of xml-dsig ns prefi attribute
     */
    public String getXmlDsigNs() {
        return m_nsXmlDsig;
    }

    /**
     * Mutator for xml-dsig ns prefi attribute
     * @param str new value for xml-dsig ns prefi attribute
     */
    public void setXmlDsigNs(String str)
    {
        m_nsXmlDsig = str;
    }

    /**
     * Accessor for xades ns prefix attribute
     * @return value of xades ns prefi attribute
     */
    public String getXadesNs() {
        return m_nsXades;
    }

    /**
     * Mutator for xades ns prefi attribute
     * @param str new value for xades ns prefi attribute
     */
    public void setXadesNs(String str)
    {
        m_nsXades = str;
    }

    /**
     * Accessor for asic ns prefix attribute
     * @return value of asic ns prefi attribute
     */
    public String getAsicNs() {
        return m_nsAsic;
    }

    /**
     * Mutator for asic ns prefi attribute
     * @param str new value for asic ns prefi attribute
     */
    public void setAsicNs(String str)
    {
        m_nsAsic = str;
    }

    /**
     * Accessor for profile attribute
     * @return value of profile attribute
     */
    public String getProfile()
    {
        return m_profile;
    }

    /**
     * Mutator for profile attribute
     * @param s new value for profile attribute
     */
    public void setProfile(String s)
    {
        m_profile = s;
    }

    /**
     * Helper method to validate a format
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateFormat(String str)
    {
        DigiDocException ex = null;
        if(str == null) {
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "Format attribute is mandatory!", null);
        } else {
            if(!str.equals(FORMAT_BDOC) && !str.equals(FORMAT_SK_XML) &&
                    !str.equals(FORMAT_DIGIDOC_XML)) {
                ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                        "Currently supports only SK-XML, DIGIDOC-XML and BDOC formats", null);
            }
            if(str.equals(SignedDoc.FORMAT_BDOC)) {
                if(m_manifest == null)
                    m_manifest = new Manifest();
                if(m_manifest.findFileEntryByPath("/") == null) {
                    ManifestFileEntry fe = new ManifestFileEntry(getManifestEntry(m_version), "/");
                    m_manifest.addFileEntry(fe);
                }
                setDefaultNsPref(SignedDoc.FORMAT_BDOC);
            }
        }
        return ex;
    }

    /**
     * Accessor for version attribute
     * @return value of version attribute
     */
    public String getVersion() {
        return m_version;
    }

    /**
     * Mutator for version attribute
     * @param str new value for version attribute
     * @throws DigiDocException for validation errors
     */
    public void setVersion(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateVersion(str);
        if(ex != null)
            throw ex;
        m_version = str;
    }

    /**
     * Helper method to validate a version
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateVersion(String str)
    {
        DigiDocException ex = null;
        if(str == null) {
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "Version attribute is mandatory!", null);
        } else {
            if(m_format != null) {
                if(m_format.equals(FORMAT_SK_XML) && !str.equals(VERSION_1_0))
                    ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION,
                            "Format SK-XML supports only version 1.0", null);
                if(m_format.equals(FORMAT_DIGIDOC_XML) && !str.equals(VERSION_1_1) &&
                        !str.equals(VERSION_1_2) && !str.equals(VERSION_1_3))
                    ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION,
                            "Format DIGIDOC-XML supports only versions 1.1, 1.2, 1.3", null);
                if(m_format.equals(FORMAT_BDOC) && !str.equals(BDOC_VERSION_2_1))
                    ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION,
                            "Format BDOC supports only versions 2.1", null);
                // don't check for XADES and XADES_T - test formats for ETSI plugin tests
            }
        }
        return ex;
    }

    /**
     * Sets a combination of format and version and validates data
     * @param sFormat format string
     * @param sVersion version string
     * @throws DigiDocException in case of invalid format/version
     */
    public void setFormatAndVersion(String sFormat, String sVersion)
            throws DigiDocException
    {
        m_format = sFormat;
        m_version = sVersion;
        DigiDocException ex = validateFormatAndVersion();
        if(ex != null) throw ex;
    }

    /**
     * Helper method to validate both format and version
     * @return exception or null for ok
     */
    public DigiDocException validateFormatAndVersion()
    {
        DigiDocException ex = null;
        if(m_format == null || m_version == null) {
            return new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "Format and version attributes are mandatory!", null);
        }
        if(m_format.equals(FORMAT_DIGIDOC_XML) || m_format.equals(FORMAT_SK_XML)) {
            if(!m_version.equals(VERSION_1_3))
                return new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                        "Only format DIGIDOC-XML version 1.3 is supported!", null);
        } else if(m_format.equals(FORMAT_BDOC)) {
            if(!m_version.equals(BDOC_VERSION_2_1))
                return new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                        "Format BDOC supports only versions 2.1", null);
        } else {
            return new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "Invalid format attribute!", null);
        }
        return null;
    }


    /**
     * Accessor for manifest attribute
     * @return value of manifest attribute
     */
    public Manifest getManifest() {
        return m_manifest;
    }

    /**
     * Mutator for manifest element
     * @param m manifest element
     */
    public void setManifest(Manifest m) {
        m_manifest = m;
    }

    /**
     * Accessor for mime-type attribute
     * @return value of mime-type attribute
     */
    public String getMimeType() {
        return m_mimeType;
    }

    /**
     * Mutator for mime-type attribute
     * @param str new value for mime-type attribute
     */
    public void setMimeType(String str)
    {
        m_mimeType = str;
    }

    /**
     * return the count of DataFile objects
     * @return count of DataFile objects
     */
    public int countDataFiles()
    {
        return ((m_dataFiles == null) ? 0 : m_dataFiles.size());
    }

    /**
     * Removes temporary DataFile cache files
     */
    public void cleanupDfCache() {
        for(int i = 0; (m_dataFiles != null) && (i < m_dataFiles.size()); i++) {
            DataFile df = (DataFile)m_dataFiles.get(i);
            df.cleanupDfCache();
        }
    }

    public InputStream findDataFileAsStream(String dfName)
    {
        try {
            if(m_file != null) {
                StringBuffer sbName = new StringBuffer();
                if(m_path != null) {
                    sbName.append(m_path);
                    sbName.append(File.separator);
                }
                sbName.append(m_file);
                File fZip = new File(sbName.toString());
                if(fZip.isFile() && fZip.canRead()) {
                    ZipFile zis = new ZipFile(fZip);
                    ZipArchiveEntry ze = zis.getEntry(dfName);
                    if(ze != null) {
                        return zis.getInputStream(ze);
                    }
                }
            }
        } catch(Exception ex) {
            m_logger.error("Error reading bdoc: " + ex);
        }
        return null;
    }

    /**
     * return a new available DataFile id
     * @retusn new DataFile id
     */
    public String getNewDataFileId()
    {
        int nDf = 0;
        String id = "D" + nDf;
        boolean bExists = false;
        do {
            bExists = false;
            for(int d = 0; d < countDataFiles(); d++) {
                DataFile df = getDataFile(d);
                if(df.getId().equals(id)) {
                    nDf++;
                    id = "D" + nDf;
                    bExists = true;
                    continue;
                }
            }
        } while(bExists);
        return id;
    }

    /**
     * Adds a new DataFile to signed doc
     * @param inputFile input file name
     * @param mime files mime type
     * @param contentType DataFile's content type
     * @return new DataFile object
     */
    public DataFile addDataFile(File inputFile, String mime, String contentType)
            throws DigiDocException
    {
        DigiDocException ex1 = validateFormatAndVersion();
        if(ex1 != null) throw ex1;
        boolean bExists = false;
        for(int i = 0; i < countDataFiles(); i++) {
            DataFile df1 = getDataFile(i);
            if(df1.getFileName().equals(inputFile.getName()))
                bExists = true;
        }
        if(bExists && m_format.equals(FORMAT_BDOC)) {
            m_logger.error("Duplicate DataFile name: " + inputFile.getName());
            throw new DigiDocException(DigiDocException.ERR_DATA_FILE_FILE_NAME,
                    "Duplicate DataFile filename: " + inputFile.getName(), null);
        }
        DataFile df = new DataFile(getNewDataFileId(), contentType, inputFile.getAbsolutePath(), mime, this);
        if(inputFile.canRead())
            df.setSize(inputFile.length());
        addDataFile(df);
        if(m_format.equals(SignedDoc.FORMAT_BDOC)) {
            df.setId(inputFile.getName());
        }
        return df;
    }

    /**
     * Makes a copy of old file to be able to extrac data from it
     * during the creation of new file
     * @param sdocFile original existing container file
     * @return new temporary file
     * @throws DigiDocException
     */
    // TODO: research if this is necessary?
    /*private File copyOldFile(File sdocFile)
    	throws DigiDocException
    {
    	File fCopy = null;
    	try {
    	  if(sdocFile.canRead()) { // if old file exists
    		fCopy = File.createTempFile("sdoc", null);
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Copying original sdoc: " + sdocFile.getAbsolutePath() + " to: " + fCopy.getAbsolutePath());
    		FileInputStream fis = new FileInputStream(sdocFile);
    		FileOutputStream fos = new FileOutputStream(fCopy);
    		byte[] data = new byte[2048];
    		int n = 0;
    		while((n = fis.read(data)) > 0)
    			fos.write(data, 0, n);
    		fis.close();
    		fos.close();
    	  }
    	} catch(Exception ex) {
    		DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
    	}
    	return fCopy;
    }*/

    /**
     * Writes the SignedDoc to an output file
     * and automatically calculates DataFile sizes
     * and digests
     * @param outputFile output file name
     * @throws DigiDocException for all errors
     */
    public void writeToFile(File outputFile)
            throws DigiDocException
    {
        try {
            OutputStream os = new FileOutputStream(outputFile);
            // make a copy of old file if it exists
            //File fCopy = copyOldFile(outputFile);
            writeToStream(os);
            os.close();
            // delete temp file
    		/*if(fCopy != null) {
    			if(m_logger.isDebugEnabled())
        			m_logger.debug("Deleting temp-file: " + fCopy.getAbsolutePath());
    			fCopy.delete();
    		}*/
        } catch(DigiDocException ex) {
            throw ex; // allready handled
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    /**
     * Writes the SignedDoc to an output file
     * and automatically calculates DataFile sizes
     * and digests
     * @param outputFile output file name
     * @param fTempSdoc temporrary file, copy of original for copying items
     * @throws DigiDocException for all errors
     */
    public void writeToStream(OutputStream os/*, File fTempSdoc*/)
            throws DigiDocException
    {
        DigiDocException ex1 = validateFormatAndVersion();
        if(ex1 != null) throw ex1;
        try {
            DigiDocXmlGenFactory genFac = new DigiDocXmlGenFactory(this);
            if(m_format.equals(SignedDoc.FORMAT_BDOC)) {
                ZipArchiveOutputStream zos = new ZipArchiveOutputStream(os);
                zos.setEncoding("UTF-8");
                if(m_logger.isDebugEnabled())
                    m_logger.debug("OS: " + ((os != null) ? "OK" : "NULL"));
                // write mimetype
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Writing: " + MIMET_FILE_NAME);
                ZipArchiveEntry ze = new ZipArchiveEntry(MIMET_FILE_NAME);
                if(m_comment == null)
                    m_comment = DigiDocGenFactory.getUserInfo(m_format, m_version);
                ze.setComment(m_comment);
                ze.setMethod(ZipArchiveEntry.STORED);
                java.util.zip.CRC32 crc = new java.util.zip.CRC32();
                if(m_version.equals(BDOC_VERSION_1_0)) {
                    ze.setSize(SignedDoc.MIMET_FILE_CONTENT_10.getBytes().length);
                    crc.update(SignedDoc.MIMET_FILE_CONTENT_10.getBytes());
                }
                if(m_version.equals(BDOC_VERSION_1_1)) {
                    ze.setSize(SignedDoc.MIMET_FILE_CONTENT_11.getBytes().length);
                    crc.update(SignedDoc.MIMET_FILE_CONTENT_11.getBytes());
                }
                if(m_version.equals(BDOC_VERSION_2_1)) {
                    ze.setSize(SignedDoc.MIMET_FILE_CONTENT_20.getBytes().length);
                    crc.update(SignedDoc.MIMET_FILE_CONTENT_20.getBytes());
                }
                ze.setCrc(crc.getValue());
                zos.putArchiveEntry(ze);
                if(m_version.equals(BDOC_VERSION_1_0)) {
                    zos.write(SignedDoc.MIMET_FILE_CONTENT_10.getBytes());
                }
                if(m_version.equals(BDOC_VERSION_1_1)) {
                    zos.write(SignedDoc.MIMET_FILE_CONTENT_11.getBytes());
                }
                if(m_version.equals(BDOC_VERSION_2_1)) {
                    zos.write(SignedDoc.MIMET_FILE_CONTENT_20.getBytes());
                }
                zos.closeArchiveEntry();
                // write manifest.xml
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Writing: " + MANIF_FILE_NAME);
                ze = new ZipArchiveEntry(MANIF_DIR_META_INF);
                ze = new ZipArchiveEntry(MANIF_FILE_NAME);
                ze.setComment(DigiDocGenFactory.getUserInfo(m_format, m_version));
                zos.putArchiveEntry(ze);
                //if(m_logger.isDebugEnabled())
                //	m_logger.debug("Writing manif:\n" + m_manifest.toString());
                zos.write(m_manifest.toXML());
                zos.closeArchiveEntry();
                // write data files
                for(int i = 0; i < countDataFiles(); i++) {
                    DataFile df = getDataFile(i);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Writing DF: " + df.getFileName() + " content: " + df.getContentType() + " df-cache: " +
                                ((df.getDfCacheFile() != null) ? df.getDfCacheFile().getAbsolutePath() : "NONE"));
                    InputStream is = null;
                    if(df.hasAccessToDataFile())
                        is = df.getBodyAsStream();
                    else
                        is = findDataFileAsStream(df.getFileName());
                    if(is != null) {
                        File dfFile = new File(df.getFileName());
                        String fileName = dfFile.getName();
                        ze = new ZipArchiveEntry(fileName);
                        if(df.getComment() == null)
                            df.setComment(DigiDocGenFactory.getUserInfo(m_format, m_version));
                        ze.setComment(df.getComment());
                        ze.setSize(dfFile.length());
                        ze.setTime((df.getLastModDt() != null) ? df.getLastModDt().getTime() : dfFile.lastModified());
                        zos.putArchiveEntry(ze);
                        byte[] data = new byte[2048];
                        int nRead = 0, nTotal = 0;
                        crc = new java.util.zip.CRC32();
                        while((nRead = is.read(data)) > 0) {
                            zos.write(data, 0, nRead);
                            nTotal += nRead;
                            crc.update(data, 0, nRead);
                        }
                        ze.setSize(nTotal);
                        ze.setCrc(crc.getValue());
                        zos.closeArchiveEntry();
                        is.close();
                    }
                }
                for(int i = 0; i < countSignatures(); i++) {
                    Signature sig = getSignature(i);
                    String sFileName = sig.getPath();
                    if(sFileName == null) {
                        if(m_version.equals(BDOC_VERSION_2_1))
                            sFileName = SIG_FILE_NAME_20 + (i+1) + ".xml";
                        else
                            sFileName = SIG_FILE_NAME + (i+1) + ".xml";
                    }
                    if(!sFileName.startsWith("META-INF"))
                        sFileName = "META-INF/" + sFileName;
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Writing SIG: " + sFileName + " orig: " + ((sig.getOrigContent() != null) ? "OK" : "NULL"));
                    ze = new ZipArchiveEntry(sFileName);
                    if(sig.getComment() == null)
                        sig.setComment(DigiDocGenFactory.getUserInfo(m_format, m_version));
                    ze.setComment(sig.getComment());
                    String sSig = null;
                    if(sig.getOrigContent() != null)
                        sSig = new String(sig.getOrigContent(), "UTF-8");
                    else
                        sSig = sig.toString();
                    if(sSig != null && !sSig.startsWith("<?xml"))
                        sSig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + sSig;
                    byte [] sdata = sSig.getBytes("UTF-8");
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Writing SIG: " + sFileName + " xml:\n---\n " + ((sSig != null) ? sSig : "NULL") + "\n---\n ");
                    ze.setSize(sdata.length);
                    crc = new java.util.zip.CRC32();
                    crc.update(sdata);
                    ze.setCrc(crc.getValue());
                    zos.putArchiveEntry(ze);
                    zos.write(sdata);
                    zos.closeArchiveEntry();
                }
                zos.close();
            } else if(m_format.equals(SignedDoc.FORMAT_DIGIDOC_XML)){ // ddoc format
                os.write(xmlHeader().getBytes());
                for(int i = 0; i < countDataFiles(); i++) {
                    DataFile df = getDataFile(i);
                    df.writeToFile(os);
                    os.write("\n".getBytes());
                }
                for(int i = 0; i < countSignatures(); i++) {
                    Signature sig = getSignature(i);
                    if(sig.getOrigContent() != null)
                        os.write(sig.getOrigContent());
                    else
                        os.write(genFac.signatureToXML(sig));
                    os.write("\n".getBytes());
                }
                os.write(xmlTrailer().getBytes());
            }
        } catch(DigiDocException ex) {
            throw ex; // allready handled
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }



    /**
     * Adds a new DataFile object
     * @param attr DataFile object to add
     */
    public void addDataFile(DataFile df)
            throws DigiDocException
    {
        if(countSignatures() > 0)
            throw new DigiDocException(DigiDocException.ERR_SIGATURES_EXIST,
                    "Cannot add DataFiles when signatures exist!", null);
        boolean bExists = false;
        for(int i = 0; i < countDataFiles(); i++) {
            DataFile df1 = getDataFile(i);
            if(df1.getFileName().equals(df.getFileName()))
                bExists = true;
        }
        if(bExists && m_format.equals(FORMAT_BDOC)) {
            m_logger.error("Duplicate DataFile name: " + df.getFileName());
            throw new DigiDocException(DigiDocException.ERR_DATA_FILE_FILE_NAME,
                    "Duplicate DataFile filename: " + df.getFileName(), null);
        }
        if(m_format.equals(SignedDoc.FORMAT_BDOC) && df.getFileName() != null) {
            df.setContentType(DataFile.CONTENT_BINARY);
            String sFile = df.getFileName();
            if(sFile.indexOf('/') != -1 || sFile.indexOf('\\') != -1) {
                File fT = new File(sFile);
                sFile = fT.getName();
            }
            if(findManifestEntryByPath(sFile) == null) {
                ManifestFileEntry fe = new ManifestFileEntry(df.getMimeType(), sFile);
                m_manifest.addFileEntry(fe);
            }
        }
        if(m_dataFiles == null)
            m_dataFiles = new ArrayList();
        if(df.getId() == null)
            df.setId(getNewDataFileId());
        m_dataFiles.add(df);
    }

    /**
     * return the desired DataFile object
     * @param idx index of the DataFile object
     * @return desired DataFile object
     */
    public DataFile getDataFile(int idx)
    {
        if(m_dataFiles != null && idx >= 0 && idx < m_dataFiles.size())
            return (DataFile)m_dataFiles.get(idx);
        else
            return null;
    }

    /**
     * return the latest DataFile object
     * @return desired DataFile object
     */
    public DataFile getLastDataFile() {
        if(m_dataFiles != null && m_dataFiles.size() > 0)
            return (DataFile)m_dataFiles.get(m_dataFiles.size()-1);
        else return null;
    }

    /**
     * Removes the datafile with the given index
     * @param idx index of the data file
     */
    public void removeDataFile(int idx)
            throws DigiDocException
    {
        if(countSignatures() > 0)
            throw new DigiDocException(DigiDocException.ERR_SIGATURES_EXIST,
                    "Cannot remove DataFiles when signatures exist!", null);
        DataFile df = getDataFile(idx);
        if(df != null) {
            m_dataFiles.remove(idx);
            if(m_manifest != null)
                m_manifest.removeFileEntryWithPath(df.getFileName());
        } else
            throw new DigiDocException(DigiDocException.ERR_DATA_FILE_ID, "Invalid DataFile index!", null);
    }

    /**
     * Returns DataFile with desired id
     * @param id Id attribute value
     * @return DataFile object or null if not found
     */
    public DataFile findDataFileById(String id)
    {
        for(int i = 0; (m_dataFiles != null) && (i < m_dataFiles.size()); i++) {
            DataFile df = (DataFile)m_dataFiles.get(i);
            if(df.getId() != null && id != null && df.getId().equals(id))
                return df;
        }
        return null;
    }

    /**
     * return the count of Signature objects
     * @return count of Signature objects
     */
    public int countSignatures()
    {
        return ((m_signatures == null) ? 0 : m_signatures.size());
    }

    /**
     * return a new available Signature id
     * @return new Signature id
     */
    public String getNewSignatureId()
    {
        int nS = 0;
        String id = "S" + nS;
        boolean bExists = false;
        do {
            bExists = false;
            for(int i = 0; i < countSignatures(); i++) {
                Signature sig = getSignature(i);
                if(sig.getId().equals(id)) {
                    nS++;
                    id = "S" + nS;
                    bExists = true;
                    continue;
                }
            }
        } while(bExists);
        return id;
    }

    /**
     * Find signature by id atribute value
     * @param sigId signature Id atribute value
     * @return signature object or null if not found
     */
    public Signature findSignatureById(String sigId)
    {
        for(int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            if(sig.getId().equals(sigId))
                return sig;
        }
        return null;
    }

    /**
     * Find signature by path atribute value
     * @param path signature path atribute value (path in bdoc container)
     * @return signature object or null if not found
     */
    public Signature findSignatureByPath(String path)
    {
        for(int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            if(sig.getPath() != null && sig.getPath().equals(path))
                return sig;
        }
        return null;
    }

    /**
     * Adds a new uncomplete signature to signed doc
     * @param cert signers certificate
     * @param claimedRoles signers claimed roles
     * @param adr signers address
     * @return new Signature object
     */
    public Signature prepareSignature(X509Certificate cert,
                                      String[] claimedRoles, SignatureProductionPlace adr)
            throws DigiDocException
    {
        DigiDocException ex1 = validateFormatAndVersion();
        if(ex1 != null) throw ex1;
        return DigiDocGenFactory.prepareXadesBES(this, m_profile, cert, claimedRoles, adr, null, null, null);
    }

    /**
     * Adds a new uncomplete signature to signed doc
     * @param cert signers certificate
     * @return new Signature object
     */
    public Signature prepareXadesTSignature(X509Certificate cert, String sigDatId, byte[] sigDatHash)
            throws DigiDocException
    {
        Signature sig = new Signature(this);
        sig.setId(getNewSignatureId());
        // create SignedInfo block
        SignedInfo si = new SignedInfo(sig, RSA_SHA1_SIGNATURE_METHOD,
                CANONICALIZATION_METHOD_20010315);
        // add DataFile references
        Reference ref = new Reference(si, "#"+sigDatId, SignedDoc.SHA1_DIGEST_ALGORITHM,
                sigDatHash, TRANSFORM_20001026);
        si.addReference(ref);
        sig.setSignedInfo(si);
        // create key info
        KeyInfo ki = new KeyInfo(cert);
        sig.setKeyInfo(ki);
        ki.setSignature(sig);
        CertValue cval = new CertValue(null, cert, CertValue.CERTVAL_TYPE_SIGNER, sig);
        sig.addCertValue(cval);
        CertID cid = new CertID(sig, cert, CertID.CERTID_TYPE_SIGNER);
        sig.addCertID(cid);
        addSignature(sig);
        UnsignedProperties usp = new UnsignedProperties(sig, null, null);
        sig.setUnsignedProperties(usp);
        return sig;
    }

    /**
     * Adds a new Signature object
     * @param attr Signature object to add
     */
    public void addSignature(Signature sig)
    {
        if(m_signatures == null)
            m_signatures = new ArrayList();
        m_signatures.add(sig);
        if(m_format != null && m_format.equals(SignedDoc.FORMAT_BDOC)) {
            Signature sig1 = null;
            if(sig.getPath() != null)
                sig1 = findSignatureByPath(sig.getPath());
            if(sig1 == null) {
                if(m_version.equals(BDOC_VERSION_2_1))
                    sig.setPath(SIG_FILE_NAME_20 + m_signatures.size() + ".xml");
                else
                    sig.setPath(SIG_FILE_NAME + m_signatures.size() + ".xml");
                // no manifest.xml entries for signatures in bdoc 2.0
                if(!m_version.equals(SignedDoc.BDOC_VERSION_2_1)) {
                    ManifestFileEntry fe = new ManifestFileEntry(SignedDoc.MIME_SIGNATURE_BDOC_ + m_version + "/" + sig.getProfile(), SignedDoc.SIG_FILE_NAME + m_signatures.size() + ".xml");
                    m_manifest.addFileEntry(fe);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Register in manifest new signature: " + sig.getId());
                }
            }
        }
    }

    /**
     * Adds a new Signature object by reading it from
     * input stream. This method can be used for example
     * during mobile signing process where the web-service
     * returns new signature in XML
     * @param is input stream
     */
    public void readSignature(InputStream is)
            throws DigiDocException
    {
        DigiDocFactory ddfac = ConfigManager.instance().getDigiDocFactory();
        Signature sig = ddfac.readSignature(this, is);
    }

    /**
     * return the desired Signature object
     * @param idx index of the Signature object
     * @return desired Signature object
     */
    public Signature getSignature(int idx)
    {
        if(m_signatures != null && idx >= 0 && idx < m_signatures.size())
            return (Signature)m_signatures.get(idx);
        else
            return null;
    }

    /**
     * Removes the desired Signature object
     * @param idx index of the Signature object
     */
    public void removeSignature(int idx)
            throws DigiDocException
    {
        if(m_signatures != null && idx >= 0 && idx < m_signatures.size())
            m_signatures.remove(idx);
        else
            throw new DigiDocException(DigiDocException.ERR_SIGNATURE_ID, "Invalid signature index: " + idx, null);
    }


    /**
     * return the latest Signature object
     * @return desired Signature object
     */
    public Signature getLastSignature() {
        if(m_signatures != null && m_signatures.size() > 0)
            return (Signature)m_signatures.get(m_signatures.size()-1);
        else
            return null;
    }

    /**
     * Deletes last signature
     */
    public void removeLastSiganture()
    {
        if(m_signatures.size() > 0)
            m_signatures.remove(m_signatures.size()-1);
    }

    /**
     * Removes signatures without value. Temporary signatures created
     * during signing process but without completing the process
     */
    public int removeSignaturesWithoutValue()
    {
        int nRemove = 0;
        boolean bOk = true;
        do {
            bOk = true;
            for(int i = 0; (m_signatures != null) && (i < m_signatures.size()) && bOk; i++) {
                Signature sig = (Signature)m_signatures.get(i);
                if(sig.getSignatureValue() == null ||
                        sig.getSignatureValue().getValue() == null ||
                        sig.getSignatureValue().getValue().length == 0) {
                    m_signatures.remove(sig);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Remove invalid sig: " + sig.getId());
                    bOk = false;
                    nRemove++;
                }
            }
        } while(!bOk);
        return nRemove;
    }

    /**
     * Helper method to validate the whole
     * SignedDoc object
     * @param bStrong flag that specifies if Id atribute value is to
     * be rigorously checked (according to digidoc format) or only
     * as required by XML-DSIG
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate(boolean bStrong)
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateFormat(m_format);
        if(ex != null)
            errs.add(ex);
        ex = validateVersion(m_version);
        if(ex != null)
            errs.add(ex);
        if(m_format != null && m_version != null &&
                (m_format.equals(SignedDoc.FORMAT_SK_XML) ||
                        (m_format.equals(SignedDoc.FORMAT_DIGIDOC_XML) && (m_version.equals(SignedDoc.VERSION_1_1) || m_version.equals(SignedDoc.VERSION_1_2))) ||
                        (m_format.equals(SignedDoc.FORMAT_BDOC) && (m_version.equals(SignedDoc.VERSION_1_0)  || m_version.equals(SignedDoc.VERSION_1_1))))) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Old and unsupported format: " + m_format + " version: " + m_version);
            ex = new DigiDocException(DigiDocException.ERR_OLD_VER, "Old and unsupported format: " + m_format + " version: " + m_version, null);
            errs.add(ex);
        }
        if(m_profile != null &&
                (m_profile.equals(SignedDoc.BDOC_PROFILE_T) ||
                        m_profile.equals(SignedDoc.BDOC_PROFILE_TS) ||
                        m_profile.equals(SignedDoc.BDOC_PROFILE_TSA))) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("T, TS and TSA profiles are currently not supported!");
            ex = new DigiDocException(DigiDocException.ERR_VERIFY, "T, TS and TSA profiles are currently not supported!", null);
            errs.add(ex);
        }

        try {
            if(getFormat() != null && getFormat().equals(SignedDoc.FORMAT_BDOC))
                DigiDocVerifyFactory.verifyManifestEntries(this, errs);
            for(int i = 0; i < countDataFiles(); i++) {
                DataFile df = getDataFile(i);
                ArrayList e = df.validate(bStrong);
                if(!e.isEmpty())
                    errs.addAll(e);
            }
            for(int i = 0; i < countSignatures(); i++) {
                Signature sig = getSignature(i);
                ArrayList e = sig.validate();
                if(!e.isEmpty())
                    errs.addAll(e);
            }
            for(int i = 0; i < countSignatures(); i++) {
                Signature sig1 = getSignature(i);
                for(int j = 0; j < countSignatures(); j++) {
                    Signature sig2 = getSignature(j);
                    if(getFormat() != null && getFormat().equals(SignedDoc.FORMAT_BDOC) &&
                            sig2.getId() != null && sig1.getId() != null && !sig2.getId().equals(sig1.getId()) &&
                            sig2.getPath() != null && sig1.getPath() != null && sig2.getPath().equals(sig1.getPath())) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Signatures: " + sig1.getId() + " and " + sig2.getId() + " are in same file: " + sig1.getPath());
                        ex = new DigiDocException(DigiDocException.ERR_PARSE_XML, "More than one signature in signatures.xml file is unsupported", null);
                        errs.add(ex);
                    }
                }
            }
        } catch(DigiDocException ex2) {
            errs.add(ex2);
        }
        return errs;
    }

    public static boolean hasFatalErrs(ArrayList lerrs)
    {
        for(int i = 0; (lerrs != null) && (i < lerrs.size()); i++) {
            DigiDocException ex = (DigiDocException)lerrs.get(i);
            if(ex.getCode() == DigiDocException.ERR_PARSE_XML) {
                return true;
            }
        }
        return false;
    }


    /**
     * Helper method to verify the whole SignedDoc object.
     * Use this method to verify all signatures
     * @param checkDate Date on which to check the signature validity
     * @param demandConfirmation true if you demand OCSP confirmation from
     * every signature
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList verify(boolean checkDate, boolean demandConfirmation)
    {
        ArrayList errs = validate(true);
        // check fatal errs
        if(hasFatalErrs(errs))
            return errs;
        // verification
        for(int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            ArrayList e = sig.verify(this, checkDate, demandConfirmation);
            if(!e.isEmpty())
                errs.addAll(e);
        }
        if(countSignatures() == 0) {
            errs.add(new DigiDocException(DigiDocException.ERR_NOT_SIGNED, "This document is not signed!", null));
        }
        return errs;
    }

    /**
     * Helper method to create the xml header
     * @return xml header
     */
    private String xmlHeader()
    {
        StringBuffer sb = new StringBuffer("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        if(m_format.equals(FORMAT_DIGIDOC_XML)) {
            sb.append("<SignedDoc format=\"");
            sb.append(m_format);
            sb.append("\" version=\"");
            sb.append(m_version);
            sb.append("\"");
            // namespace
            if(m_version.equals(VERSION_1_3)) {
                sb.append(" xmlns=\"");
                sb.append(xmlns_digidoc13);
                sb.append("\"");
            }
            sb.append(">\n");
        }
        return sb.toString();
    }

    /**
     * Helper method to create the xml trailer
     * @return xml trailer
     */
    private String xmlTrailer()
    {
        if(m_format.equals(FORMAT_DIGIDOC_XML))
            return "\n</SignedDoc>";
        else
            return "";
    }

    /**
     * Converts the SignedDoc to XML form
     * @return XML representation of SignedDoc
     */
    public String toXML()
            throws DigiDocException
    {
        StringBuffer sb = new StringBuffer(xmlHeader());
        for(int i = 0; i < countDataFiles(); i++) {
            DataFile df = getDataFile(i);
            String str = df.toString();
            sb.append(str);
            sb.append("\n");
        }
        for(int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            String str = sig.toString();
            sb.append(str);
            sb.append("\n");
        }
        sb.append(xmlTrailer());
        return sb.toString();
    }

    /**
     * return the stringified form of SignedDoc
     * @return SignedDoc string representation
     */
    public String toString()
    {
        String str = null;
        try {
            str = toXML();
        } catch(Exception ex) {}
        return str;
    }

    /**
     * Computes an SHA1 digest
     * @param data input data
     * @return SHA1 digest
     */
    public static byte[] digest(byte[] data)
            throws DigiDocException
    {
        return digestOfType(data, SHA1_DIGEST_TYPE);
    }

    /**
     * Computes a digest
     * @param data input data
     * @param digType digest type
     * @return digest value
     */
    public static byte[] digestOfType(byte[] data, String digType)
            throws DigiDocException
    {
        byte[] dig = null;
        try {
            MessageDigest sha = MessageDigest.getInstance(digType, "BC");
            sha.update(data);
            dig = sha.digest();
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        return dig;
    }

    /**
     * Retrieves DN part with given field name
     * @param sDn DN in string form according to RFC1779 or later
     * @param sField field name
     * @param sOid OID value if known as alternative field name
     * @return field content
     */
    private static String getDnPart(String sDn, String sField, String sOid)
    {
        if(sDn != null && sDn.length() > 0) {
            String s = sField + "=";
            boolean bQ = false;
            int n1 = sDn.toUpperCase().indexOf(s.toUpperCase());
            if(n1 == -1 && sOid != null) {
                s = "OID." + sOid + "=";
                n1 = sDn.toUpperCase().indexOf(s.toUpperCase());
            }
            if(n1 >= 0) {
                n1 += s.length();
                if(sDn.charAt(n1) == '\"') {
                    bQ = true;
                    n1++;
                }
                int n2 = sDn.indexOf(bQ ? "\", " : ", ", n1);
                if(n2 == -1) n2 = sDn.length();
                if(n2 > n1 && n2 <= sDn.length())
                    return sDn.substring(n1, n2);
            }
        }
        return null;
    }

    /**
     * return certificate owners first name
     * @return certificate owners first name or null
     */
    public static String getSubjectFirstName(X509Certificate cert) {
        String dn = getDN(cert);
        String name = null;
        String cn = getDnPart(dn, "CN", null);
        if(cn != null) {
            int idx1 = 0;
            while(idx1 < cn.length() && cn.charAt(idx1) != ',')
                idx1++;
            if(idx1 < cn.length())
                idx1++;
            int idx2 = idx1;
            while(idx2 < cn.length() && cn.charAt(idx2) != ',' && cn.charAt(idx2) != '/')
                idx2++;
            name = cn.substring(idx1, idx2);
        }
        return name;
    }


    /**
     * return certificate owners last name
     * @return certificate owners last name or null
     */
    public static String getSubjectLastName(X509Certificate cert) {
        String dn = getDN(cert);
        String name = null;
        String cn = getDnPart(dn, "CN", null);
        if(cn != null) {
            int idx1 = 0;
            while(idx1 < cn.length() && !Character.isLetter(cn.charAt(idx1)))
                idx1++;
            int idx2 = idx1;
            while(idx2 < cn.length() && cn.charAt(idx2) != ',' && dn.charAt(idx2) != '/')
                idx2++;
            name = cn.substring(idx1, idx2);
        }
        return name;
    }

    /**
     * return certificate owners personal code
     * @return certificate owners personal code or null
     */
    public static String getSubjectPersonalCode(X509Certificate cert) {
        String dn = getDN(cert);
        String code = getDnPart(dn, "SERIALNUMBER", "2.5.4.5");
        if(code != null)
            return code;
        String cn = getDnPart(dn, "CN", null);
        if(cn != null) {
            int idx1 = 0;
            while(idx1 < cn.length() && !Character.isDigit(cn.charAt(idx1)))
                idx1++;
            int idx2 = idx1;
            while(idx2 < cn.length() && Character.isDigit(cn.charAt(idx2)))
                idx2++;
            if(idx2 > idx1 + 7)
                code = cn.substring(idx1, idx2);
        }
        return code;
    }

    /**
     * Returns certificates DN field in RFC1779 format
     * @param cert certificate
     * @return DN field
     */
    private static String getDN(X509Certificate cert) {
        return cert.getSubjectX500Principal().getName("RFC1779");
    }

    /**
     * return CN part of DN
     * @return CN part of DN or null
     */
    public static String getCommonName(String dn) {
        return getDnPart(dn, "CN", null);
    }


    /**
     * Reads X509 certificate from a data stream
     * @param data input data in Base64 form
     * @return X509Certificate object
     * @throws EFormException for all errors
     */
    public static X509Certificate readCertificate(byte[] data)
            throws DigiDocException
    {
        X509Certificate cert = null;
        try {
            ByteArrayInputStream certStream = new ByteArrayInputStream(data);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate)cf.generateCertificate(certStream);
            certStream.close();
        } catch(Exception ex) {
            m_logger.error("Error reading certificate: " + ex);
            //DigiDocException.handleException(ex, DigiDocException.ERR_READ_CERT);
            return null;
        }
        return cert;
    }

    /**
     * Reads in data file
     * @param inFile input file
     */
    public static byte[] readFile(File inFile)
            throws IOException, FileNotFoundException
    {
        byte[] data = null;
        FileInputStream is = new FileInputStream(inFile);
        DataInputStream dis = new DataInputStream(is);
        data = new byte[dis.available()];
        dis.readFully(data);
        dis.close();
        is.close();
        return data;
    }

    /**
     * Reads the cert from a file
     * @param certFile certificates file name
     * @return certificate object
     */
    public static X509Certificate readCertificate(File certFile)
            throws DigiDocException
    {
        X509Certificate cert = null;
        try {
            FileInputStream fis = new FileInputStream(certFile);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate)certificateFactory.generateCertificate(fis);
            fis.close();
            //byte[] data = readFile(certFile);
            //cert = readCertificate(data);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        return cert;
    }

    private static final String PEM_HDR1 = "-----BEGIN CERTIFICATE-----\n";
    private static final String PEM_HDR2 = "\n-----END CERTIFICATE-----";

    /**
     * Writes the cert from a file
     * @param cert certificate
     * @param certFile certificates file name
     * @return true for success
     */
    public static boolean writeCertificate(X509Certificate cert, File certFile)
            throws DigiDocException
    {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(certFile);
            fos.write(PEM_HDR1.getBytes());
            fos.write(Base64Util.encode(cert.getEncoded()).getBytes());
            fos.write(PEM_HDR2.getBytes());
            fos.close();
            fos = null;
            //byte[] data = readFile(certFile);
            //cert = readCertificate(data);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        } finally {
            if(fos != null) {
                try {
                    fos.close();
                } catch(Exception ex2) {
                    m_logger.error("Error closing streams: " + ex2);
                }
            }
        }
        return false;
    }

    /**
     * Reads the cert from a file, URL or from another
     * location somewhere in the CLASSPATH such as
     * in the librarys jar file.
     * @param certLocation certificates file name,
     * or URL. You can use url in form jar://<location> to read
     * a certificate from the car file or some other location in the
     * CLASSPATH
     * @return certificate object
     */
    public static X509Certificate readCertificate(String certLocation)
            throws DigiDocException
    {
        X509Certificate cert = null;
        InputStream isCert = null;
        try {
            URL url = null;
            if(certLocation.startsWith("http")) {
                url = new URL(certLocation);
                isCert = url.openStream();
            } else if(certLocation.startsWith("jar://")) {
                ClassLoader cl = ConfigManager.instance().getClass().getClassLoader();
                isCert = cl.getResourceAsStream(certLocation.substring(6));
            } else {
                isCert = new FileInputStream(certLocation);
            }
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate)certificateFactory.generateCertificate(isCert);
            isCert.close();
            isCert = null;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        } finally {
            if(isCert != null) {
                try {
                    isCert.close();
                } catch(Exception ex2) {
                    m_logger.error("Error closing streams: " + ex2);
                }
            }
        }
        return cert;
    }

    /**
     * Helper method for comparing
     * digest values
     * @param dig1 first digest value
     * @param dig2 second digest value
     * @return true if they are equal
     */
    public static boolean compareDigests(byte[] dig1, byte[] dig2)
    {
        boolean ok = (dig1 != null) && (dig2 != null) &&
                (dig1.length == dig2.length);
        for(int i = 0; ok && (i < dig1.length); i++)
            if(dig1[i] != dig2[i])
                ok = false;
        return ok;
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


}