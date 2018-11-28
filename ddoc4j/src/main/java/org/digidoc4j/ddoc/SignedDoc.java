package org.digidoc4j.ddoc;

import org.digidoc4j.ddoc.factory.DigiDocXmlGenFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
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
    /** supported versions are 1.0 and 1.1 */
    public static final String VERSION_1_0 = "1.0";
    public static final String VERSION_1_1 = "1.1";
    public static final String VERSION_1_2 = "1.2";
    public static final String VERSION_1_3 = "1.3";
    public static final String PROFILE_TM = "TM";
    /** the only supported algorithm for ddoc is SHA1 */
    public static final String SHA1_DIGEST_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#sha1";
    public static final String SHA1_DIGEST_TYPE="SHA-1";
    public static final String SHA1_DIGEST_TYPE_BAD="SHA-1-00";

    /** SHA1 digest data is allways 20 bytes */
    public static final int SHA1_DIGEST_LENGTH = 20;
    /** SHA224 digest data is allways 28 bytes */
    /** the only supported canonicalization method is 20010315 */
    public static final String CANONICALIZATION_METHOD_20010315 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /** canonical xml 1.1 */
    public static final String CANONICALIZATION_METHOD_1_1 = "http://www.w3.org/2006/12/xml-c14n11";
    public static final String CANONICALIZATION_METHOD_2010_10_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String TRANSFORM_20001026 = "http://www.w3.org/TR/2000/CR-xml-c14n-20001026";
    /** the only supported signature method is RSA-SHA1 */
    public static final String RSA_SHA1_SIGNATURE_METHOD = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    /** elliptic curve algorithms */
    public static final String ECDSA_SHA1_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";

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
    /** Xades namespace */
    public static String xmlns_xades_123 = "http://uri.etsi.org/01903/v1.3.2#";

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
    }

    public void setDefaultNsPref(String format)
    {
        if(format.equals(SignedDoc.FORMAT_DIGIDOC_XML) || format.equals(SignedDoc.FORMAT_SK_XML)) {
            m_nsXmlDsig = null;
            m_nsXades = null;
            m_nsAsic = null;
        }
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
            if(!str.equals(FORMAT_SK_XML) && !str.equals(FORMAT_DIGIDOC_XML)) {
                ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                        "Currently supports only SK-XML and DIGIDOC-XML formats", null);
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
        DataFile df = new DataFile(getNewDataFileId(), contentType, inputFile.getAbsolutePath(), mime, this);
        if(inputFile.canRead())
            df.setSize(inputFile.length());
        addDataFile(df);
        return df;
    }

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
    public void writeToStream(OutputStream os)
            throws DigiDocException
    {
        DigiDocException ex1 = validateFormatAndVersion();
        if(ex1 != null) throw ex1;
        try {
            DigiDocXmlGenFactory genFac = new DigiDocXmlGenFactory(this);
            if(m_format.equals(SignedDoc.FORMAT_DIGIDOC_XML)){ // ddoc format
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
     * return the count of Signature objects
     * @return count of Signature objects
     */
    public int countSignatures()
    {
        return ((m_signatures == null) ? 0 : m_signatures.size());
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
     * Adds a new Signature object
     * @param attr Signature object to add
     */
    public void addSignature(Signature sig)
    {
        if(m_signatures == null)
            m_signatures = new ArrayList();
        m_signatures.add(sig);
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
                        (m_format.equals(SignedDoc.FORMAT_DIGIDOC_XML) && (m_version.equals(SignedDoc.VERSION_1_1) || m_version.equals(SignedDoc.VERSION_1_2))))) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Old and unsupported format: " + m_format + " version: " + m_version);
            ex = new DigiDocException(DigiDocException.ERR_OLD_VER, "Old and unsupported format: " + m_format + " version: " + m_version, null);
            errs.add(ex);
        }
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