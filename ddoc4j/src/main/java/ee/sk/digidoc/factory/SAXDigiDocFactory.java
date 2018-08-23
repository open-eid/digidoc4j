package ee.sk.digidoc.factory;

import ee.sk.digidoc.*;
import ee.sk.utils.ConfigManager;
import ee.sk.utils.ConvertUtils;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * SAX implementation of DigiDocFactory
 * Provides methods for reading a DigiDoc file
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SAXDigiDocFactory
        extends DefaultHandler
        implements DigiDocFactory
{
    private Stack m_tags;
    private SignedDoc m_doc;
    private Signature m_sig;
    private String m_strSigValTs, m_strSigAndRefsTs;
    private StringBuffer m_sbCollectChars;
    private StringBuffer m_sbCollectItem;
    private StringBuffer m_sbCollectSignature;
    private boolean m_bCollectDigest;
    private String m_xmlnsAttr;
    /** This mode means collect SAX events into xml data
     * and is used to collect all <DataFile>, <SignedInfo> and
     * <SignedProperties> content. Also servers as level of
     * embedded DigiDoc files. Initially it should be 0. If
     * we start collecting data then it's 1 and if we find
     * another SignedDoc inside a DataFile then it will be incremented
     * in order to know which is the correct </DataFile> tag to leave
     * the collect mode
     */
    private int m_nCollectMode;
    private long nMaxBdocFilCached;
    /** log4j logger */
    private Logger m_logger = LoggerFactory.getLogger(SAXDigiDocFactory.class);
    /** calculation of digest */
    private MessageDigest m_digest, m_altDigest;
    /** temp output stream used to cache DataFile content */
    private FileOutputStream m_dfCacheOutStream;
    private String m_tempDir;
    /** name of file being loaded */
    private String m_fileName, m_sigComment;
    private String m_nsDsPref, m_nsXadesPref, m_nsAsicPref;
    private List m_errs;
    private XmlElemInfo m_elemRoot, m_elemCurrent;

    public static final String FILE_MIMETYPE = "mimetype";
    public static final String FILE_MANIFEST = "META-INF/manifest.xml";
    public static final String CONTENTS_MIMETYPE = "application/vnd.bdoc";
    public static final String CONTENTS_MIMETYPE_1_0 = "application/vnd.bdoc-1.0";
    public static final String MIME_SIGNATURE_BDOC = "signature/bdoc";
    public static final String FILE_SIGNATURES = "META-INF/signature";
    /**
     * Creates new SAXDigiDocFactory
     * and initializes the variables
     */
    public SAXDigiDocFactory() {
        m_tags = new Stack();
        m_doc = null;
        m_sig = null;
        m_sbCollectSignature = null;
        m_xmlnsAttr = null;
        m_nsAsicPref = null;
        m_sbCollectItem = null;
        m_digest = null;
        m_altDigest = null;
        m_bCollectDigest = false;
        m_dfCacheOutStream = null;
        m_tempDir = null;
        m_errs = null;
        m_elemRoot = null;
        m_elemCurrent = null;
        nMaxBdocFilCached = ConfigManager.instance().
                getLongProperty("DIGIDOC_MAX_DATAFILE_CACHED", Long.MAX_VALUE);
    }

    /**
     * Helper method to update sha1 digest with some data
     * @param data
     */
    private void updateDigest(byte[] data)
    {
        try {
            // if not inited yet then initialize digest
            if(m_digest == null)
                m_digest = MessageDigest.getInstance("SHA-1");
            m_digest.update(data);
        } catch(Exception ex) {
            m_logger.error("Error calculating digest: " + ex);
            //ex.printStackTrace();
        }
    }

    /**
     * Helper method to update alternate sha1 digest with some data
     * @param data
     */
    private void updateAltDigest(byte[] data)
    {
        try {
            // if not inited yet then initialize digest
            if(m_altDigest == null)
                m_altDigest = MessageDigest.getInstance("SHA-1");
            m_altDigest.update(data);
        } catch(Exception ex) {
            m_logger.error("Error calculating digest: " + ex);
            //ex.printStackTrace();
        }
    }

    /**
     * Set temp dir used to cache data files.
     * @param s directory name
     */
    public void setTempDir(String s) {
        m_tempDir = s;
    }

    /**
     * Helper method to calculate the digest result and
     * reset digest
     * @return sha-1 digest value
     */
    private byte[] getDigest()
    {
        byte [] digest = null;
        try {
            // if not inited yet then initialize digest
            digest = m_digest.digest();
            m_digest = null; // reset for next calculation
        } catch(Exception ex) {
            m_logger.error("Error calculating digest: " + ex);
            //ex.printStackTrace();
        }
        return digest;
    }

    /**
     * Helper method to calculate the alternate digest result and
     * reset digest
     * @return sha-1 digest value
     */
    private byte[] getAltDigest()
    {
        byte [] digest = null;
        try {
            // if not inited yet then initialize digest
            digest = m_altDigest.digest();
            m_altDigest = null; // reset for next calculation
        } catch(Exception ex) {
            m_logger.error("Error calculating digest: " + ex);
            //ex.printStackTrace();
        }
        return digest;
    }

    /**
     * initializes the implementation class
     */
    public void init() throws DigiDocException {
    }

    /**
     * Checks filename extension if this is bdoc / asic-e
     * @param fname filename
     * @return true if this is bdoc / asic-e
     */
    public boolean isBdocExtension(String fname)
    {
        return fname.endsWith(".bdoc") ||
                fname.endsWith(".asice") ||
                fname.endsWith(".sce");
    }

    /**
     * Checks if this stream could be a bdoc input stream
     * @param is input stream, must support mark() and reset() operations!
     * @return true if bdoc
     */
    private boolean isBdocFile(InputStream is)
            throws DigiDocException
    {
        try {
            if(is.markSupported())
                is.mark(10);
            byte[] tdata = new byte[10];
            int n = is.read(tdata);
            if(is.markSupported())
                is.reset();
            if(n >= 2 && tdata[0] == (byte)'P' && tdata[1] == (byte)'K')
                return true; // probably a zip file
            if(n >= 5 && tdata[0] == (byte)'<' && tdata[1] == (byte)'?' &&
                    tdata[2] == (byte)'x' && tdata[3] == (byte)'m' &&
                    tdata[4] == (byte)'l')
                return false; // an xml file - probably ddoc format?
        } catch(Exception ex) {
            m_logger.error("Error determining file type: " + ex);
        }
        return false;
    }

    /**
     * Checks if this file contains the correct bdoc mimetype
     * @param zis ZIP input stream
     * @return true if correct bdoc
     */
    private boolean checkBdocMimetype(InputStream zis)
            throws DigiDocException
    {
        try {
            byte[] data = new byte[100];
            int nRead = zis.read(data);
            if(nRead >= CONTENTS_MIMETYPE.length()) {
                //skip leading whitespace & BOM marks
                String s2 = new String(data, 0, nRead), s = null;
                for(int i = 0; i < nRead; i++) {
                    if(s2.charAt(i) == 'a') { // search application/...
                        s = s2.substring(i);
                        break;
                    }
                }
                if(s == null)
                    s = new String(data);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("MimeType: \'" + s + "\'" + " len: " + s.length());
                if(s.trim().equals(SignedDoc.MIMET_FILE_CONTENT_10)) {
                    m_doc.setVersion(SignedDoc.BDOC_VERSION_1_0);
                    m_doc.setFormat(SignedDoc.FORMAT_BDOC);
                    throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "Format BDOC supports only version 2.1", null);

                } else if(s.trim().equals(SignedDoc.MIMET_FILE_CONTENT_11)) {
                    m_doc.setVersion(SignedDoc.BDOC_VERSION_1_1);
                    m_doc.setFormat(SignedDoc.FORMAT_BDOC);
                    throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "Format BDOC supports only version 2.1", null);

                } else if(s.trim().equals(SignedDoc.MIMET_FILE_CONTENT_20)) {
                    m_doc.setVersion(SignedDoc.BDOC_VERSION_2_1);
                    m_doc.setFormat(SignedDoc.FORMAT_BDOC);
                    m_doc.setProfile(SignedDoc.BDOC_PROFILE_TM);
                    return true;
                } else if(s.trim().startsWith(CONTENTS_MIMETYPE)) {
                    throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "Invalid BDOC version!", null);
                } else { // no bdoc or wrong version
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Invalid MimeType: \'" + s + "\'" + " len: " + s.length() + " expecting: " + CONTENTS_MIMETYPE.length());
                    throw new DigiDocException(DigiDocException.ERR_DIGIDOC_BADXML,
                            "Not a BDOC format file!", null);
                }
            } else {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Invalid empty MimeType");
                throw new DigiDocException(DigiDocException.ERR_DIGIDOC_BADXML,
                        "Not a BDOC format file! MimeType file is empty!", null);
            }
        } catch(DigiDocException ex) {
            m_logger.error("Mimetype err: " + ex);
            //ex.printStackTrace();
            throw ex;
        } catch(Exception ex) {
            m_logger.error("Error reading mimetype file: " + ex);
        }
        return false;
    }


    private void handleError(Exception err)
            throws DigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Handle err: " + err + " list: " + (m_errs != null));
        err.printStackTrace();

        DigiDocException err1 = null;
        if(err instanceof SAXDigiDocException) {
            err1 = ((SAXDigiDocException)err).getDigiDocException();
        } else if(err instanceof DigiDocException) {
            err1 = (DigiDocException)err;
            err1.printStackTrace();
            if(err1.getNestedException() != null)
                err1.getNestedException().printStackTrace();
        } else
            err1 = new DigiDocException(DigiDocException.ERR_PARSE_XML, "Invalid xml file!", err);

        if(m_errs != null)
            m_errs.add(err1);
        else
            throw err1;
    }

    private void handleSAXError(Exception err)
            throws SAXDigiDocException
    {
        if(m_logger.isDebugEnabled()) {
            m_logger.debug("Handle sa err: " + err + " list: " + (m_errs != null));
            m_logger.debug("Trace: " + ConvertUtils.getTrace(err));
        }
        DigiDocException err1 = null;
        SAXDigiDocException err2 = null;
        if(err instanceof SAXDigiDocException) {
            err1 = ((SAXDigiDocException)err).getDigiDocException();
            err2 = (SAXDigiDocException)err;
        } else if(err instanceof DigiDocException) {
            err1 = (DigiDocException)err;
            err2 = new SAXDigiDocException(err.getMessage());
            err2.setNestedException(err);
        } else {
            err1 = new DigiDocException(0, err.getMessage(), null);
            err2 = new SAXDigiDocException(err.getMessage());
            err2.setNestedException(err);
        }
        if(m_errs != null)
            m_errs.add(err1);
        else
            throw err2;
    }


    /**
     * Reads in a DigiDoc file. One of fname or isSdoc must be given.
     * @param fname signed doc filename
     * @param isSdoc opened stream with DigiDoc data
     * The user must open and close it.
     * @param errs list of errors to fill with parsing errors. If given
     * then attempt is made to continue parsing on errors and return them in this list.
     * If not given (null) then the first error found will be thrown.
     * @return signed document object if successfully parsed
     */
    private SignedDoc readSignedDocOfType(String fname, InputStream isSdoc, boolean isBdoc, List errs)
            throws DigiDocException
    {
        // Use an instance of ourselves as the SAX event handler
        SAXDigiDocFactory handler = this;
        m_errs = errs;
        DigiDocVerifyFactory.initProvider();
        SAXParserFactory factory = SAXParserFactory.newInstance();
        if(m_logger.isDebugEnabled())
            m_logger.debug("Start reading ddoc/bdoc " + ((fname != null) ? "from file: " + fname : "from stream") + " bdoc: " + isBdoc);
        if(fname == null && isSdoc == null) {
            throw new DigiDocException(DigiDocException.ERR_READ_FILE, "No input file", null);
        }
        if(fname != null) {
            File inFile = new File(fname);
            if(!inFile.canRead() || inFile.length() == 0) {
                throw new DigiDocException(DigiDocException.ERR_READ_FILE, "Empty or unreadable input file", null);
            }
        }
        ZipFile zf = null;
        ZipArchiveInputStream zis = null;
        ZipArchiveEntry ze = null;
        InputStream isEntry = null;
        File fTmp = null;
        try {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            if(isBdoc) { // bdoc parsing
                // must be a bdoc document ?
                m_doc = new SignedDoc();
                m_doc.setVersion(SignedDoc.BDOC_VERSION_1_0);
                m_doc.setFormat(SignedDoc.FORMAT_BDOC);
                Enumeration eFiles = null;
                if(fname != null) {
                    zf = new ZipFile(fname, "UTF-8");
                    eFiles = zf.getEntries();
                } else if(isSdoc != null) {
                    zis = new ZipArchiveInputStream(isSdoc, "UTF-8", true, true);
                }
                ArrayList lSigFnames = new ArrayList();
                ArrayList lDataFnames = new ArrayList();
                // read all entries
                boolean bHasMimetype = false, bManifest1 = false;
                int nFil = 0;
                while((zf != null && eFiles.hasMoreElements()) ||
                        (zis != null && ((ze = zis.getNextZipEntry()) != null)) ) {
                    nFil++;

                    // read entry
                    if(zf != null) { // ZipFile
                        ze = (ZipArchiveEntry)eFiles.nextElement();
                        isEntry = zf.getInputStream(ze);
                    } else { // ZipArchiveInputStream
                        int n = 0, nTot = 0;
                        if((ze.getName().equals(FILE_MIMETYPE) ||
                                ze.getName().equals(FILE_MANIFEST) ||
                                (ze.getName().startsWith(FILE_SIGNATURES) &&
                                        ze.getName().endsWith(".xml"))) ||
                                (nMaxBdocFilCached <= 0 || (ze.getSize() < nMaxBdocFilCached && ze.getSize() >= 0))) {
                            ByteArrayOutputStream bos = new ByteArrayOutputStream();
                            byte[] data = new byte[2048];
                            while((n = zis.read(data)) > 0) {
                                bos.write(data, 0, n);
                                nTot += n;
                            }
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("Read: " + nTot + " bytes from zip");
                            data = bos.toByteArray();
                            bos = null;
                            isEntry = new ByteArrayInputStream(data);
                        } else {
                            File fCacheDir = new File(ConfigManager.instance().
                                    getStringProperty("DIGIDOC_DF_CACHE_DIR", System.getProperty("java.io.tmpdir")));
                            fTmp = File.createTempFile("bdoc-data", ".tmp", fCacheDir);
                            FileOutputStream fos = new FileOutputStream(fTmp);
                            byte[] data = new byte[2048];
                            while((n = zis.read(data)) > 0) {
                                fos.write(data, 0, n);
                                nTot += n;
                            }
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("Read: " + nTot + " bytes from zip to: " + fTmp.getAbsolutePath());
                            fos.close();
                            isEntry = new FileInputStream(fTmp);
                        }
                    }
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Entry: " + ze.getName() + " nlen: " + ze.getName().length() + " size: " + ze.getSize() + " dir: " + ze.isDirectory() + " comp-size: " + ze.getCompressedSize());
                    // mimetype file
                    if(ze.getName().equals(FILE_MIMETYPE)) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Check mimetype!");
                        checkBdocMimetype(isEntry);
                        bHasMimetype = true;
                        m_doc.setComment(ze.getComment());
                        if(nFil != 1) {
                            m_logger.error("mimetype file is " + nFil + " file but must be first");
                            handleError(new DigiDocException(DigiDocException.ERR_DIGIDOC_BADXML,
                                    "mimetype file is not first zip entry", null));
                        }
                    } else if(ze.getName().equals(FILE_MANIFEST)) { // manifest.xml file
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Read manifest");
                        if(!bManifest1 && isEntry != null) {
                            bManifest1 = true;
                            BdocManifestParser mfparser = new BdocManifestParser(m_doc);
                            mfparser.readManifest(isEntry);
                        } else {
                            m_logger.error("Found multiple manifest.xml files!");
                            throw new DigiDocException(DigiDocException.ERR_MULTIPLE_MANIFEST_FILES,
                                    "Found multiple manifest.xml files!", null);
                        }
                    } else if(ze.getName().startsWith(FILE_SIGNATURES) &&
                            ze.getName().endsWith(".xml")) { // some signature
                        m_fileName = ze.getName();
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Reading bdoc siganture: " + m_fileName);
                        boolean bExists = false;
                        for(int j = 0; j < lSigFnames.size(); j++) {
                            String s1 = (String)lSigFnames.get(j);
                            if(s1.equals(m_fileName))
                                bExists = true;
                        }
                        if(bExists) {
                            m_logger.error("Duplicate signature filename: " + m_fileName);
                            handleError(new DigiDocException(DigiDocException.ERR_DIGIDOC_BADXML,
                                    "Duplicate signature filename: " + m_fileName, null));
                        } else
                            lSigFnames.add(m_fileName);
                        SAXParser saxParser = factory.newSAXParser();
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        int n = 0;
                        byte[] data = new byte[2048];
                        while((n = isEntry.read(data)) > 0)
                            bos.write(data, 0, n);
                        data = bos.toByteArray();
                        bos = null;
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Parsing bdoc: " + m_fileName + " size: " + ((data != null) ? data.length : 0));
                        saxParser.parse(new SignatureInputStream(new ByteArrayInputStream(data)), this);
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Parsed bdoc: " + m_fileName);
                        Signature sig1 = m_doc.getLastSignature();
                        m_sigComment = ze.getComment();
                        if(sig1 != null) {
                            sig1.setPath(m_fileName);
                            sig1.setComment(ze.getComment());
                        }
                    } else { // probably a data file
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Read data file: " + ze.getName());
                        if(!ze.isDirectory()) {
                            boolean bExists = false;
                            for(int j = 0; j < lDataFnames.size(); j++) {
                                String s1 = (String)lDataFnames.get(j);
                                if(s1.equals(ze.getName()))
                                    bExists = true;
                            }
                            if(bExists) {
                                m_logger.error("Duplicate datafile filename: " + ze.getName());
                                handleError(new DigiDocException(DigiDocException.ERR_DIGIDOC_BADXML,
                                        "Duplicate datafile filename: " + ze.getName(), null));
                            } else
                                lDataFnames.add(ze.getName());
                            DataFile df = m_doc.findDataFileById(ze.getName());
                            if(df != null) {
                                if(ze.getSize() > 0)
                                    df.setSize(ze.getSize());
                                df.setContentType(DataFile.CONTENT_BINARY);
                                df.setFileName(ze.getName());
                            } else {
                                df = new DataFile(ze.getName(), DataFile.CONTENT_BINARY, ze.getName(), "application/binary", m_doc);
                                if(m_doc.getDataFiles() == null)
                                    m_doc.setDataFiles(new ArrayList());
                                m_doc.getDataFiles().add(df);
                                //m_doc.addDataFile(df); // this does some intiailization work unnecessary here
                            }
                            // enable caching if requested
                            if(isEntry != null)
                                df.setOrCacheBodyAndCalcHashes(isEntry);
                            df.setComment(ze.getComment());
                            df.setLastModDt(new Date(ze.getTime()));
                            // fix mime type according to DataObjectFormat
                            Signature sig1 = m_doc.getLastSignature();
                            if(sig1 != null) {
                                Reference dRef = sig1.getSignedInfo().getReferenceForDataFile(df);
                                if(dRef != null) {
                                    DataObjectFormat dof = sig1.getSignedInfo().getDataObjectFormatForReference(dRef);
                                    if(dof != null) {
                                        df.setMimeType(dof.getMimeType());
                                    }
                                }
                            }
                        }
                    }
                    if(fTmp != null) {
                        fTmp.delete();
                        fTmp = null;
                    }
                } // while zip entries
                if(!bHasMimetype) {
                    m_logger.error("No mimetype file");
                    handleError(new DigiDocException(DigiDocException.ERR_DIGIDOC_BADXML,
                            "Not a BDOC format file! No mimetype file!", null));
                }
                // if no signatures exist then copy mime-type from manifest.xml to DataFile -s
                if(m_doc.countSignatures() == 0) {
                    for(int i = 0; i < m_doc.countDataFiles(); i++) {
                        DataFile df = m_doc.getDataFile(i);
                        if(m_doc.getManifest() != null) {
                            for(int j = 0; j < m_doc.getManifest().getNumFileEntries(); j++) {
                                ManifestFileEntry mfe = m_doc.getManifest().getFileEntry(j);
                                if(mfe.getFullPath() != null && mfe.getFullPath().equals(df.getFileName())) {
                                    df.setMimeType(mfe.getMediaType());
                                } // if fullpath
                            } // for
                        } // if
                    } // for i
                }
            } else { // ddoc parsing
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Reading ddoc: " + fname + " file: " + m_fileName);
                m_fileName = fname;
                SAXParser saxParser = factory.newSAXParser();
                if(fname != null)
                    saxParser.parse(new SignatureInputStream(new FileInputStream(fname)), this);
                else if(isSdoc != null)
                    saxParser.parse(isSdoc, this);
            }
        } catch(org.xml.sax.SAXParseException ex) {
            m_logger.error("SAX Error: " + ex);
            handleError(ex);

        } catch (Exception ex) {
            m_logger.error("Error reading3: " + ex);
            ex.printStackTrace();
			/*if(ex instanceof DigiDocException){
				DigiDocException dex = (DigiDocException)ex;
				m_logger.error("Dex: " + ex);
				if(dex.getNestedException() != null) {
					dex.getNestedException().printStackTrace();
					m_logger.error("Trace: ");
				}
			}*/
            handleError(ex);
        } finally { // cleanup
            try {
                if(isEntry != null) {
                    isEntry.close();
                    isEntry = null;
                }
                if(zis != null)
                    zis.close();
                if(zf != null)
                    zf.close();
                if(fTmp != null) {
                    fTmp.delete();
                    fTmp = null;
                }
            } catch(Exception ex) {
                m_logger.error("Error closing streams and files: " + ex);
            }
        }
        // compare Manifest and DataFiles
        boolean bErrList = (errs != null);
        if(errs == null)
            errs = new ArrayList();
        boolean bOk = DigiDocVerifyFactory.verifyManifestEntries(m_doc, errs);
        if(m_doc == null) {
            m_logger.error("Error reading4: doc == null");
            handleError(new DigiDocException(DigiDocException.ERR_DIGIDOC_BADXML,
                    "This document is not in ddoc or bdoc format", null));
        }
        if(!bErrList && errs.size() > 0) { // if error list was not used then we have to throw exception. So we will throw the first one since we can only do it once
            DigiDocException ex = (DigiDocException)errs.get(0);
            throw ex;
        }
        return m_doc;
    }



    /**
     * Reads in a DigiDoc or BDOC file
     * @param fname filename
     * @param isBdoc true if bdoc is read
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocOfType(String fname, boolean isBdoc)
            throws DigiDocException
    {
        return readSignedDocOfType(fname, null, isBdoc, null);
    }

    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * @param is opened stream with DigiDoc/BDOC data
     * The user must open and close it.
     * @param isBdoc true if bdoc is read
     * @return signed document object if successfully parsed
     * @deprecated use readSignedDocFromStreamOfType(InputStream is, boolean isBdoc, List lerr)
     */
    public SignedDoc readSignedDocFromStreamOfType(InputStream is, boolean isBdoc)
            throws DigiDocException
    {
        return readSignedDocOfType(null, is, isBdoc, null);
    }

    /**
     * Reads in a DigiDoc or BDOC file
     * @param fname filename
     * @param isBdoc true if bdoc is read
     * @param lerr list of errors to be filled. If not null then no exceptions are thrown
     * but returned in this array
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocOfType(String fname, boolean isBdoc, List lerr)
            throws DigiDocException
    {
        return readSignedDocOfType(fname, null, isBdoc, lerr);
    }

    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * @param is opened stream with DigiDoc/BDOC data
     * The user must open and close it.
     * @param isBdoc true if bdoc is read
     * @param lerr list of errors to be filled. If not null then no exceptions are thrown
     * but returned in this array
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocFromStreamOfType(InputStream is, boolean isBdoc, List lerr)
            throws DigiDocException
    {
        return readSignedDocOfType(null, is, isBdoc, lerr);
    }

    /**
     * Reads in a DigiDoc file.This method reads only data in digidoc format. Not BDOC!
     * @param digiDocStream opened stream with DigiDoc data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public SignedDoc readDigiDocFromStream(InputStream digiDocStream)
            throws DigiDocException
    {
        DigiDocVerifyFactory.initProvider();
        if(m_logger.isDebugEnabled())
            m_logger.debug("Start reading ddoc/bdoc");
        try {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Reading ddoc");
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(digiDocStream, this);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (m_doc == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "This document is not in digidoc", null);
        return m_doc;
    }


    /**
     * Reads in a DigiDoc file
     * @param fileName file name
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(String fileName)
            throws DigiDocException
    {
        try {
            FileInputStream fis = new FileInputStream(fileName);
            boolean bdoc = isBdocFile(fis);
            fis.close();
            SignedDoc sdoc = readSignedDocOfType(fileName, bdoc);
            File f = new File(fileName);
            m_fileName = fileName;
            sdoc.setFile(f.getName());
            String s = f.getAbsolutePath();
            int n = s.lastIndexOf(File.separator);
            if(n > 0) {
                s = s.substring(0,n);
                sdoc.setPath(s);
            }
            return sdoc;
        } catch (DigiDocException ex) {
            throw ex;
        } catch(java.io.FileNotFoundException ex) {
            throw new DigiDocException(DigiDocException.ERR_READ_FILE,
                    "File not found: " + fileName, null);
        } catch(java.io.IOException ex) {
            throw new DigiDocException(DigiDocException.ERR_READ_FILE,
                    "Error determning file type: " + fileName, null);
        }
    }

    /**
     * Reads in a DigiDoc file
     * @param digiSigStream opened stream with Signature data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public Signature readSignature(InputStream digiSigStream)
            throws DigiDocException
    {
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(digiSigStream, this);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (m_sig == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "This document is not in signature format", null);
        return m_sig;
    }

    /**
     * Reads in only one <Signature>
     * @param sdoc SignedDoc to add this signature to
     * @param sigStream opened stream with Signature data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public Signature readSignature(SignedDoc sdoc, InputStream sigStream)
            throws DigiDocException
    {
        m_doc = sdoc;
        m_nCollectMode = 0;
        try {
            // prepare validator to receive signature from xml file as root element
            if(sdoc != null && sdoc.getFormat() != null) {
                XmlElemInfo e = null;
                // for BDOC
                if(SignedDoc.FORMAT_BDOC.equals(sdoc.getFormat())) {
                    e = new XmlElemInfo("XAdESSignatures", null, null);
                } else if(SignedDoc.FORMAT_DIGIDOC_XML.equals(sdoc.getFormat())) {
                    e = new XmlElemInfo("SignedDoc", null, null);
                }
                if(e != null)
                    m_elemRoot = m_elemCurrent = e;
            }
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(sigStream, this);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex,
                    DigiDocException.ERR_PARSE_XML);
        }
        if (m_doc.getLastSignature() == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "This document is not in Signature format", null);
        return m_doc.getLastSignature();
    }

    /**
     * Helper method to canonicalize a piece of xml
     * @param xml data to be canonicalized
     * @return canonicalized xml
     */
    private String canonicalizeXml(String xml) {
        try {
            CanonicalizationFactory canFac = ConfigManager.
                    instance().getCanonicalizationFactory();
            byte[] tmp = canFac.canonicalize(xml.getBytes("UTF-8"),
                    SignedDoc.CANONICALIZATION_METHOD_20010315);
            return new String(tmp, "UTF-8");
        } catch(Exception ex) {
            m_logger.error("Canonicalizing exception: " + ex);
        }
        return null;
    }

    public SignedDoc getSignedDoc() {
        return m_doc;
    }

    public Signature getLastSignature() {
        if(m_doc != null)
            return m_doc.getLastSignature();
        else
            return m_sig;
    }

    /**
     * Start Document handler
     */
    public void startDocument() throws SAXException {
        m_nCollectMode = 0;
        m_xmlnsAttr = null;
        m_dfCacheOutStream = null;
        m_nsDsPref = null;
        m_nsXadesPref = null;
        m_nsAsicPref = null;
    }

    private void findCertIDandCertValueTypes(Signature sig)
    {
        if(m_logger.isDebugEnabled() && sig != null)
            m_logger.debug("Sig: " + sig.getId() + " certids: " + sig.countCertIDs());
        for(int i = 0; (sig != null) && (i < sig.countCertIDs()); i++) {
            CertID cid = sig.getCertID(i);
            if(cid != null && cid.getType() == CertID.CERTID_TYPE_UNKNOWN) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("CertId: " + cid.getId() + " type: " + cid.getType() + " nr: " + cid.getSerial());
                CertValue cval = sig.findCertValueWithSerial(cid.getSerial());
                if(cval != null) {
                    String cn = null;
                    try {
                        cn = SignedDoc.
                                getCommonName(cval.getCert().getSubjectDN().getName());
                        if(m_logger.isDebugEnabled() && cid != null)
                            m_logger.debug("CertId type: " + cid.getType() + " nr: " + cid.getSerial() + " cval: " + cval.getId() + " CN: " + cn);
                        if(ConvertUtils.isKnownOCSPCert(cn)) {
                            if(m_logger.isInfoEnabled())
                                m_logger.debug("Cert: " + cn + " is OCSP responders cert");
                            cid.setType(CertID.CERTID_TYPE_RESPONDER);
                            cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                        }
                        if(ConvertUtils.isKnownTSACert(cn)) {
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("Cert: " + cn + " is TSA cert");
                            cid.setType(CertID.CERTID_TYPE_TSA);
                            cval.setType(CertValue.CERTVAL_TYPE_TSA);
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("CertId: " + cid.getId() + " type: " + cid.getType() + " nr: " + cid.getSerial());
                        }
                    } catch(DigiDocException ex) {
                        m_logger.error("Error setting type on certid or certval: " + cn);
                    }
                }
            }

        } // for i < sig.countCertIDs()
        if(m_logger.isDebugEnabled())
            m_logger.debug("Sig: " + sig.getId() + " certvals: " + sig.countCertValues());
        for(int i = 0; (sig != null) && (i < sig.countCertValues()); i++) {
            CertValue cval = sig.getCertValue(i);
            if(m_logger.isDebugEnabled() && cval != null)
                m_logger.debug("CertValue: " + cval.getId() + " type: " + cval.getType());
            if(cval.getType() == CertValue.CERTVAL_TYPE_UNKNOWN) {
                String cn = null;
                try {
                    cn = SignedDoc.
                            getCommonName(cval.getCert().getSubjectDN().getName());
                    if(ConvertUtils.isKnownOCSPCert(cn)) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Cert: " + cn + " is OCSP responders cert");
                        cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                    }
                    if(ConvertUtils.isKnownTSACert(cn)) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Cert: " + cn + " is TSA cert");
                        cval.setType(CertValue.CERTVAL_TYPE_TSA);
                    }
                } catch(DigiDocException ex) {
                    m_logger.error("Error setting type on certid or certval: " + cn);
                }
            }
        }
    }

    private String findXmlElemContents(String str, String tag, String id)
    {
        String s1 = "<" + tag;
        String s2 = "</" + tag + ">";
        int nIdx1 = 0, nIdx2 = 0, nIdx3 = 0, nIdx4 = 0;
        while((nIdx1 = str.indexOf(s1, nIdx1)) > 0) {
            nIdx2 = str.indexOf(">", nIdx1);
            if(nIdx2 > 0) {
                nIdx3 = str.indexOf("Id", nIdx1);
                if(nIdx3 > 0 && nIdx3 < nIdx2) {
                    nIdx3 = str.indexOf("\"", nIdx3);
                    nIdx4 = str.indexOf("\"", nIdx3+1);
                    if(nIdx3 > nIdx1 && nIdx3 < nIdx2 && nIdx4 > nIdx1 && nIdx4 < nIdx2) {
                        String sId = str.substring(nIdx3+1, nIdx4);
                        if(sId.equals(id)) {
                            nIdx2 = str.indexOf(s2, nIdx2);
                            if(nIdx2 > nIdx1) {
                                nIdx2 += s2.length() + 1;
                                String sEl = str.substring(nIdx1, nIdx2);
                                if(m_logger.isDebugEnabled())
                                    m_logger.debug("Elem: " + tag + " id: " + id + "\n---\n" + sEl + "\n---\n");
                                return sEl;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }


    /**
     * End Document handler
     */
    public void endDocument()
            throws SAXException
    {
    }


    private String findNsPrefForUri(Attributes attrs, String uri)
    {
        for(int i = 0; i < attrs.getLength(); i++) {
            String key = attrs.getQName(i);
            String val = attrs.getValue(i);
            if(val.equals(uri)) {
                int p = key.indexOf(':');
                if(p > 0)
                    return key.substring(p+1);
                else
                    return null;
            }
        }
        return null;
    }

    private String findAttrValueByName(Attributes attrs, String aName)
    {
        for(int i = 0; i < attrs.getLength(); i++) {
            String key = attrs.getQName(i);
            if (key.equalsIgnoreCase(aName)) {
                return attrs.getValue(i);
            }
        }
        return null;
    }

    /**
     * Start Element handler
     * @param namespaceURI namespace URI
     * @param lName local name
     * @param qName qualified name
     * @param attrs attributes
     */
    public void startElement(String namespaceURI, String lName, String qName, Attributes attrs)
            throws SAXDigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Start Element: "	+ qName + " lname: "  + lName + " uri: " + namespaceURI);
        String tag = qName;
        if(tag.indexOf(':') != -1) {
            tag = qName.substring(qName.indexOf(':') + 1);
            if(m_nsDsPref == null) {
                m_nsDsPref = findNsPrefForUri(attrs, xmlnsDs);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Element: " + qName + " xmldsig pref: " + ((m_nsDsPref != null) ? m_nsDsPref : "NULL"));
            }
            if(m_nsXadesPref == null) {
                m_nsXadesPref = findNsPrefForUri(attrs, xmlnsEtsi);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Element: " + qName + " xades pref: " + ((m_nsXadesPref != null) ? m_nsXadesPref : "NULL"));
            }
            if(m_nsAsicPref == null) {
                m_nsAsicPref = findNsPrefForUri(attrs, xmlnsAsic);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Element: " + qName + " asic pref: " + ((m_nsAsicPref != null) ? m_nsAsicPref : "NULL"));
            }
        }
        // record elements found
        XmlElemInfo e = new XmlElemInfo(tag, findAttrValueByName(attrs, "id"),
                (tag.equals("XAdESSignatures") || tag.equals("SignedDoc")) ? null : m_elemCurrent);
        // <XAdESSignatures> and <SignedDoc> cannot be child of another element, must be root elements
        if(m_elemCurrent != null && !tag.equals("XAdESSignatures") && !tag.equals("SignedDoc"))
            m_elemCurrent.addChild(e);
        m_elemCurrent = e;
        if(m_elemRoot == null || tag.equals("XAdESSignatures") || tag.equals("SignedDoc"))
            m_elemRoot = e;
        DigiDocException exv = DigiDocStructureValidator.validateElementPath(m_elemCurrent);
        if(exv != null)
            handleSAXError(exv);

        m_tags.push(tag);
        if(tag.equals("SigningTime") ||
                tag.equals("IssuerSerial") ||
                tag.equals("X509SerialNumber") ||
                tag.equals("X509IssuerName") ||
                tag.equals("ClaimedRole") ||
                tag.equals("City") ||
                tag.equals("StateOrProvince") ||
                tag.equals("CountryName") ||
                tag.equals("PostalCode") ||
                tag.equals("SignatureValue") ||
                tag.equals("DigestValue") ||
                //qName.equals("EncapsulatedX509Certificate") ||
                tag.equals("IssuerSerial") ||
                (tag.equals("ResponderID") && !m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) ||
                (tag.equals("ByName") && m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC) ) ||
                (tag.equals("ByKey") && m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) ||
                tag.equals("X509SerialNumber") ||
                tag.equals("ProducedAt") ||
                tag.equals("EncapsulatedTimeStamp") ||
                tag.equals("Identifier") ||
                tag.equals("SPURI") ||
                tag.equals("NonceAlgorithm") ||
                tag.equals("MimeType") ||
                tag.equals("EncapsulatedOCSPValue") ) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Start collecting tag: " + tag);
            m_sbCollectItem = new StringBuffer();
        }
        // <XAdESSignatures>
        if(tag.equals("XAdESSignatures")) {
            try {
                if (m_logger.isDebugEnabled())
                    m_logger.debug("BDOC 2.0 - ASIC-E");
                m_doc.setFormatAndVersion(SignedDoc.FORMAT_BDOC, SignedDoc.BDOC_VERSION_2_1);
            } catch(DigiDocException ex) {
                handleSAXError(ex);
            }
        }

        // <X509Certificate>
        // Prepare CertValue object
        if(tag.equals("X509Certificate")) {
            Signature sig = getLastSignature();
            CertValue cval = null;
            try {
                if (m_logger.isDebugEnabled())
                    m_logger.debug("Adding signers cert to: " + sig.getId());
                cval = sig.getOrCreateCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
            } catch(DigiDocException ex) {
                handleSAXError(ex);
            }
            m_sbCollectItem = new StringBuffer();
        }
        // <EncapsulatedX509Certificate>
        // Prepare CertValue object and record it's id
        if(tag.equals("EncapsulatedX509Certificate")) {
            Signature sig = getLastSignature();
            String id = null;
            for(int i = 0; i < attrs.getLength(); i++) {
                String key = attrs.getQName(i);
                if (key.equalsIgnoreCase("Id")) {
                    id = attrs.getValue(i);
                }
            }
            CertValue cval = new CertValue();
            if(id != null) {
                cval.setId(id);
                try {
                    if(id.indexOf("RESPONDER_CERT") != -1 ||
                            id.indexOf("RESPONDER-CERT") != -1)
                        cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                } catch(DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            if(m_logger.isDebugEnabled() && cval != null)
                m_logger.debug("Adding cval " + cval.getId() + " type: " + cval.getType() + " to: " + sig.getId());
            sig.addCertValue(cval);
            m_sbCollectItem = new StringBuffer();
        }
        // the following elements switch collect mode
        // in and out
        // <DataFile>
        boolean bDfDdoc13Bad = false;
        if(tag.equals("DataFile")) {
            String ContentType = null, Filename = null, Id = null, MimeType = null, Size = null, DigestType = null, Codepage = null;
            byte[] DigestValue = null;
            m_digest = null; // init to null
            if (m_doc != null &&
                    m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) &&
                    m_doc.getVersion().equals(SignedDoc.VERSION_1_3)) {
                m_xmlnsAttr = SignedDoc.xmlns_digidoc13;
                bDfDdoc13Bad = true; // possible case for ddoc 1.3 invalid namespace problem
            } else
                m_xmlnsAttr = null;
            ArrayList dfAttrs = new ArrayList();
            for (int i = 0; i < attrs.getLength(); i++) {
                String key = attrs.getQName(i);
                if (key.equals("ContentType")) {
                    ContentType = attrs.getValue(i);
                } else if (key.equals("Filename")) {
                    Filename = attrs.getValue(i);
                    if(Filename.indexOf('/') != -1 || Filename.indexOf('\\') != -1) {
                        DigiDocException ex = new DigiDocException(DigiDocException.ERR_DF_NAME, "Failed to parse DataFile name. Invalid file name!", null);
                        handleSAXError(ex);
                    }
                } else if (key.equals("Id")) {
                    Id = attrs.getValue(i);
                } else if (key.equals("MimeType")) {
                    MimeType = attrs.getValue(i);
                } else if (key.equals("Size")) {
                    Size = attrs.getValue(i);
                } else if (key.equals("DigestType")) {
                    DigestType = attrs.getValue(i);
                } else if (key.equals("Codepage")) {
                    Codepage = attrs.getValue(i);
                } else if (key.equals("DigestValue")) {
                    DigestValue = Base64Util.decode(attrs.getValue(i));
                } else {
                    try {
                        if (!key.equals("xmlns")) {
                            DataFileAttribute attr = new DataFileAttribute(key, attrs.getValue(i));
                            dfAttrs.add(attr);
                        } else {
                            bDfDdoc13Bad = false; // nope, this one has it's own xmlns
                        }
                    } catch (DigiDocException ex) {
                        handleSAXError(ex);
                    }
                } // else
            } // for
            if(m_nCollectMode == 0) {
                try {
                    DataFile df = new DataFile(Id, ContentType, Filename, MimeType, m_doc);
                    m_dfCacheOutStream = null; // default is don't use cache file
                    if (Size != null)
                        df.setSize(Long.parseLong(Size));
                    if (DigestValue != null) {
                        if(m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML))
                            df.setAltDigest(DigestValue);
                        else if(ContentType != null && ContentType.equals(DataFile.CONTENT_HASHCODE))
                            df.setDigestValue(DigestValue);
                    }
                    if (Codepage != null)
                        df.setInitialCodepage(Codepage);
                    for (int i = 0; i < dfAttrs.size(); i++)
                        df.addAttribute((DataFileAttribute) dfAttrs.get(i));
                    // enable caching if requested
                    if(m_tempDir != null) {
                        File fCache = new File(m_tempDir + File.separator + df.getFileName());
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Parser temp DF: " + Id + " size: " + df.getSize() +
                                    " cache-file: " + fCache.getAbsolutePath());
                        m_dfCacheOutStream = new FileOutputStream(fCache);
                        df.setCacheFile(fCache);
                    } else if(df.schouldUseTempFile()) {
                        File fCache = df.createCacheFile();
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Df-temp DF: " + Id + " size: " + df.getSize() +
                                    " cache-file: " + fCache.getAbsolutePath());
                        df.setCacheFile(fCache);
                        m_dfCacheOutStream = new FileOutputStream(fCache);
                    }
                    m_doc.addDataFile(df);
                } catch (IOException ex) {
                    handleSAXError(ex);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            m_nCollectMode++;
            // try to anticipate how much memory we need for collecting this <DataFile>
            try {
                if(Size != null) {
                    int nSize = Integer.parseInt(Size);
                    if(!ContentType.equals(DataFile.CONTENT_HASHCODE)) {
                        if(ContentType.equals(DataFile.CONTENT_EMBEDDED_BASE64)) {
                            nSize *= 2;
                            m_bCollectDigest = true;
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("Start collecting digest");
                        }
                        if(m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML))
                            m_bCollectDigest = false;
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Allocating buf: " + nSize + " Element: "	+ qName + " lname: "  + lName + " uri: " + namespaceURI);
                        if(m_dfCacheOutStream == null) // if we use temp files then we don't cache in memory
                            m_sbCollectChars = new StringBuffer(nSize);
                    }
                }
            } catch(Exception ex) {
                m_logger.error("Error: " + ex);
            }
        }

        //
        if(tag.equals("SignedInfo")) {
            if (m_nCollectMode == 0) {
                try {
                    if (m_doc != null &&
                            (m_doc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                                    m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC) ||
                                    m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)))
                        m_xmlnsAttr = null;
                    else
                        m_xmlnsAttr = SignedDoc.xmlns_xmldsig;
                    Signature sig = getLastSignature();
                    SignedInfo si = new SignedInfo(sig);
                    if(sig != null) {
                        sig.setSignedInfo(si);
                        String Id = attrs.getValue("Id");
                        if(Id != null)
                            si.setId(Id);
                    }
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            m_nCollectMode++;
            m_sbCollectChars = new StringBuffer(1024);
        }
        // <SignedProperties>
        if(tag.equals("SignedProperties")) {
            String Id = attrs.getValue("Id");
            String Target = attrs.getValue("Target");
            if (m_nCollectMode == 0) {
                try {
                    if(m_doc != null &&
                            (m_doc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                                    m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC)))
                        m_xmlnsAttr = null;
                    else
                        m_xmlnsAttr = SignedDoc.xmlns_xmldsig;
                    Signature sig = getLastSignature();
                    SignedProperties sp = new SignedProperties(sig);
                    sp.setId(Id);
                    if(Target != null)
                        sp.setTarget(Target);
                    sig.setSignedProperties(sp);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            m_nCollectMode++;
            m_sbCollectChars = new StringBuffer(2048);
        }
        // <XAdESSignatures>
        if(tag.equals("XAdESSignatures") && m_nCollectMode == 0) {
            if (m_logger.isDebugEnabled())
                m_logger.debug("Start collecting <XAdESSignatures>");
            m_sbCollectSignature = new StringBuffer();
        }
        // <Signature>
        if(tag.equals("Signature") && m_nCollectMode == 0) {
            if (m_logger.isDebugEnabled())
                m_logger.debug("Start collecting <Signature>");
            if(m_doc == null) {
                DigiDocException ex = new DigiDocException(DigiDocException.ERR_PARSE_XML, "Invalid signature format. Missing signed container root element.", null);
                handleSAXError(ex); // now stop parsing
                SAXDigiDocException sex1 = new SAXDigiDocException("Invalid signature format. Missing signed container root element.");
                throw sex1;
            }
            String str1 = attrs.getValue("Id");
            Signature sig = null;
            // in case of ddoc-s try find existing signature but not in case of bdoc-s.
            // to support libc++ buggy implementation with non-unique id atributes
            if(m_doc != null && !m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                sig = m_doc.findSignatureById(str1);
            if(m_doc != null && m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC) &&
                    m_doc.getVersion().equals(SignedDoc.BDOC_VERSION_2_1)) {
                m_doc.addSignatureProfile(str1, SignedDoc.BDOC_PROFILE_TM);
                if(m_doc.getProfile() == null || !m_doc.getProfile().equals(SignedDoc.BDOC_PROFILE_TM))
                    m_doc.setProfile(SignedDoc.BDOC_PROFILE_TM);
            }
            if(sig == null || (sig.getId() != null && !sig.getId().equals(str1))) {
                if (m_logger.isDebugEnabled())
                    m_logger.debug("Create signature: " + str1);
                if(m_doc != null) {
                    sig = new Signature(m_doc);
                    try {
                        sig.setId(str1);
                    } catch (DigiDocException ex) {
                        handleSAXError(ex);
                    }
                    sig.setPath(m_fileName);
                    sig.setComment(m_sigComment);
                    String sProfile = m_doc.findSignatureProfile(m_fileName);
                    if(sProfile == null)
                        sProfile = m_doc.findSignatureProfile(sig.getId());
                    if(sProfile != null)
                        sig.setProfile(sProfile);
					/*if(sProfile == null &&
							(m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
									m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)))
						sig.setProfile(SignedDoc.BDOC_PROFILE_TM);*/
                    m_doc.addSignature(sig);
                    if (m_logger.isDebugEnabled())
                        m_logger.debug("Sig1: " + m_fileName + " profile: " + sProfile + " doc: " + ((m_doc != null) ? "OK" : "NULL"));
                } else {
                    m_sig = new Signature(null);
                    m_sig.setPath(m_fileName);
                    m_sig.setComment(m_sigComment);
                    String sProfile = null;
                    if(m_doc != null && m_fileName != null)
                        sProfile = m_doc.findSignatureProfile(m_fileName);
                    if(sProfile != null)
                        m_sig.setProfile(sProfile);
                    if (m_logger.isDebugEnabled())
                        m_logger.debug("Sig2: " + m_fileName + " profile: " + sProfile);
                    sig = m_sig;
                }
                for(int j = 0; (m_doc != null) && (j < m_doc.countSignatures()); j++) {
                    Signature sig2 = m_doc.getSignature(j);
                    if(sig2 != null && sig != null && m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC) &&
                            sig2.getId() != null && sig.getId() != null && !sig2.getId().equals(sig.getId()) &&
                            sig2.getPath() != null && sig.getPath() != null && sig2.getPath().equals(sig.getPath())) {
                        m_logger.error("Signatures: " + sig.getId() + " and " + sig2.getId() + " are in same file: " + sig.getPath());
                        DigiDocException ex = new DigiDocException(DigiDocException.ERR_PARSE_XML, "More than one signature in signatures.xml file is unsupported", null);
                        handleSAXError(ex);
                    }
                }
            }
            if(m_sbCollectSignature == null)
                m_sbCollectSignature = new StringBuffer();
        }
        // <SignatureValue>
        if(tag.equals("SignatureValue") && m_nCollectMode == 0) {
            m_strSigValTs = null;
            m_nCollectMode++;
            m_sbCollectChars = new StringBuffer(1024);
        }
        // <SignatureTimeStamp>
        if(tag.equals("SignatureTimeStamp") && m_nCollectMode == 0) {
            if(m_sig != null) m_sig.setProfile(SignedDoc.BDOC_PROFILE_TS);
            m_doc.setProfile(SignedDoc.BDOC_PROFILE_TS);
            m_strSigAndRefsTs = null;
            m_nCollectMode++;
            m_sbCollectChars = new StringBuffer(2048);
        }
        // collect <Signature> data
        if(m_sbCollectSignature != null) {
            m_sbCollectSignature.append("<");
            m_sbCollectSignature.append(qName);
            for (int i = 0; i < attrs.getLength(); i++) {
                m_sbCollectSignature.append(" ");
                m_sbCollectSignature.append(attrs.getQName(i));
                m_sbCollectSignature.append("=\"");
                String s = attrs.getValue(i);
                s = s.replaceAll("&", "&amp;");
                m_sbCollectSignature.append(s);
                m_sbCollectSignature.append("\"");
            }
            m_sbCollectSignature.append(">");
        }
        // if we just switched to collect-mode
        // collect SAX event data to original XML data
        // for <DataFile> we don't collect the begin and
        // end tags unless this an embedded <DataFile>
        if(m_nCollectMode > 0 || m_sbCollectChars != null) {
            StringBuffer sb = new StringBuffer();
            String sDfTagBad = null;
            sb.append("<");
            sb.append(qName);
            for (int i = 0; i < attrs.getLength(); i++) {
                if(attrs.getQName(i).equals("xmlns")) {
                    m_xmlnsAttr = null; // allready have it from document
                    bDfDdoc13Bad = false;
                }
                sb.append(" ");
                sb.append(attrs.getQName(i));
                sb.append("=\"");
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Attr: " + attrs.getQName(i) + " =\'" + attrs.getValue(i) + "\'");

                if(!m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                    sb.append(ConvertUtils.escapeXmlSymbols(attrs.getValue(i)));
                } else {
                    String sv = attrs.getValue(i);
                    if(attrs.getQName(i).equals("DigestValue") && sv.endsWith(" "))
                        sv = sv.replaceAll(" ", "\n");
                    sb.append(sv);
                }
                sb.append("\"");
            }
            if(bDfDdoc13Bad)
                sDfTagBad = sb.toString() + ">";
            if (m_xmlnsAttr != null) {
                sb.append(" xmlns=\"" + m_xmlnsAttr + "\"");
                m_xmlnsAttr = null;
            }
            sb.append(">");
            //canonicalize & calculate digest over DataFile begin-tag without content
            if(tag.equals("DataFile") && m_nCollectMode == 1) {
                String strCan = null;
                if(!m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                    strCan = sb.toString() + "</DataFile>";
                    strCan = canonicalizeXml(strCan);
                    strCan = strCan.substring(0, strCan.length() - 11);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Canonicalized: \'" + strCan + "\'");
                    if(sDfTagBad != null) {
                        strCan = sDfTagBad + "</DataFile>";
                        strCan = canonicalizeXml(strCan);
                        sDfTagBad = strCan.substring(0, strCan.length() - 11);
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Canonicalized alternative: \'" + sDfTagBad + "\'");
                    }
                    try {
                        updateDigest(ConvertUtils.str2data(strCan));
                        if(sDfTagBad != null)
                            updateAltDigest(ConvertUtils.str2data(sDfTagBad));
                    } catch (DigiDocException ex) {
                        handleSAXError(ex);
                    }
                }
            } // we don't collect <DataFile> begin and end - tags and we don't collect if we use temp files
            else {
                if(m_sbCollectChars != null)
                    m_sbCollectChars.append(sb.toString());
                try {
                    if(m_dfCacheOutStream != null)
                        m_dfCacheOutStream.write(ConvertUtils.str2data(sb.toString()));
                } catch (IOException ex) {
                    handleSAXError(ex);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
        }

        // the following stuff is used also on level 1
        // because it can be part of SignedInfo or SignedProperties
        if(m_nCollectMode == 1)  {
            // <CanonicalizationMethod>
            if(tag.equals("CanonicalizationMethod")) {
                String Algorithm = attrs.getValue("Algorithm");
                try {
                    Signature sig = getLastSignature();
                    SignedInfo si = sig.getSignedInfo();
                    si.setCanonicalizationMethod(Algorithm);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            // <SignatureMethod>
            if(tag.equals("SignatureMethod")) {
                String Algorithm = attrs.getValue("Algorithm");
                try {
                    Signature sig = getLastSignature();
                    SignedInfo si = sig.getSignedInfo();
                    si.setSignatureMethod(Algorithm);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            // <Reference>
            if(tag.equals("Reference")) {
                String URI = attrs.getValue("URI");
                try {
                    Signature sig = getLastSignature();
                    SignedInfo si = sig.getSignedInfo();
                    Reference ref = new Reference(si);
                    String Id = attrs.getValue("Id");
                    if(Id != null)
                        ref.setId(Id);
                    ref.setUri(ConvertUtils.unescapeXmlSymbols(ConvertUtils.uriDecode(URI)));
                    String sType = attrs.getValue("Type");
                    if(sType != null)
                        ref.setType(sType);
                    si.addReference(ref);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            // <Transform>
			/*if(tag.equals("Transform")) {
				String Algorithm = attrs.getValue("Algorithm");
				if(m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC) ||
				   m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)) {
				DigiDocException ex = new DigiDocException(DigiDocException.ERR_TRANSFORMS, "Transform elements are currently not supported ", null);
				handleSAXError(ex);
				}
			}*/
            // <X509SerialNumber>
            if(tag.equals("X509SerialNumber") && m_doc != null
                    && m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML))
            {
                String sXmlns = attrs.getValue("xmlns");
                if(sXmlns == null || !sXmlns.equals(SignedDoc.xmlns_xmldsig)) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("X509SerialNumber has none or invalid namespace: " + sXmlns);
                    DigiDocException ex = new DigiDocException(DigiDocException.ERR_ISSUER_XMLNS, "X509SerialNumber has none or invalid namespace: " + sXmlns, null);
                    handleSAXError(ex);
                }
            }
            // <X509IssuerName>
            if(tag.equals("X509IssuerName") && m_doc != null
                    && m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML))
            {
                String sXmlns = attrs.getValue("xmlns");
                if(sXmlns == null || !sXmlns.equals(SignedDoc.xmlns_xmldsig)) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("X509IssuerName has none or invalid namespace: " + sXmlns);
                    DigiDocException ex = new DigiDocException(DigiDocException.ERR_ISSUER_XMLNS, "X509IssuerName has none or invalid namespace: " + sXmlns, null);
                    handleSAXError(ex);
                }
            }
            // <SignatureProductionPlace>
            if(tag.equals("SignatureProductionPlace")) {
                try {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp =
                            new SignatureProductionPlace();
                    sp.setSignatureProductionPlace(spp);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
        }
        // the following is collected anyway independent of collect mode
        // <SignatureValue>
        if(tag.equals("SignatureValue")) {
            String Id = attrs.getValue("Id");
            try {
                Signature sig = getLastSignature();
                SignatureValue sv = new SignatureValue(sig, Id);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <OCSPRef>
        if(tag.equals("OCSPRef")) {
            OcspRef orf = new OcspRef();
            Signature sig = getLastSignature();
            UnsignedProperties usp = sig.getUnsignedProperties();
            CompleteRevocationRefs rrefs = usp.getCompleteRevocationRefs();
            rrefs.addOcspRef(orf);
        }
        // <DigestMethod>
        if(tag.equals("DigestMethod")) {
            String Algorithm = attrs.getValue("Algorithm");
            try {
                if(m_tags.search("Reference") != -1) {
                    Signature sig = getLastSignature();
                    SignedInfo si = sig.getSignedInfo();
                    Reference ref = si.getLastReference();
                    ref.setDigestAlgorithm(Algorithm);
                } else if(m_tags.search("SigningCertificate") != -1) {
                    Signature sig = getLastSignature();
                    CertID cid = sig.getOrCreateCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                    cid.setDigestAlgorithm(Algorithm);
                } else if(m_tags.search("CompleteCertificateRefs") != -1) {
                    Signature sig = getLastSignature();
                    CertID cid = sig.getLastCertId(); // initially set to unknown type !
                    cid.setDigestAlgorithm(Algorithm);
                } else if(m_tags.search("CompleteRevocationRefs") != -1) {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    OcspRef orf = rrefs.getLastOcspRef();
                    if(orf != null)
                        orf.setDigestAlgorithm(Algorithm);
                } else if(m_tags.search("SigPolicyHash") != -1) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignaturePolicyIdentifier spi = sp.getSignaturePolicyIdentifier();
                    SignaturePolicyId sppi = spi.getSignaturePolicyId();
                    sppi.setDigestAlgorithm(Algorithm);
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <Cert>
        if(tag.equals("Cert")) {
            String id = attrs.getValue("Id");
            try {
                Signature sig = getLastSignature();
                if(m_tags.search("SigningCertificate") != -1) {
                    CertID cid = sig.getOrCreateCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                    if(id != null)
                        cid.setId(id);
                }
                if(m_tags.search("CompleteCertificateRefs") != -1) {
                    //CertID cid = new CertID();
                    CertID cid = sig.getOrCreateCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
                    if(id != null)
                        cid.setId(id);
                    sig.addCertID(cid);
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <AllDataObjectsTimeStamp>
        if(tag.equals("AllDataObjectsTimeStamp")) {
            String id = attrs.getValue("Id");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_ALL_DATA_OBJECTS);
                sig.addTimestampInfo(ts);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <IndividualDataObjectsTimeStamp>
        if(tag.equals("IndividualDataObjectsTimeStamp")) {
            String id = attrs.getValue("Id");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_INDIVIDUAL_DATA_OBJECTS);
                sig.addTimestampInfo(ts);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <SignatureTimeStamp>
        if(tag.equals("SignatureTimeStamp")) {
            String id = attrs.getValue("Id");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
                sig.addTimestampInfo(ts);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <SigAndRefsTimeStamp>
        if(tag.equals("SigAndRefsTimeStamp")) {
            String id = attrs.getValue("Id");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS);
                sig.addTimestampInfo(ts);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <RefsOnlyTimeStamp>
        if(tag.equals("RefsOnlyTimeStamp")) {
            String id = attrs.getValue("Id");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_REFS_ONLY);
                sig.addTimestampInfo(ts);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <ArchiveTimeStamp>
        if(tag.equals("ArchiveTimeStamp")) {
            String id = attrs.getValue("Id");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_ARCHIVE);
                sig.addTimestampInfo(ts);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <Include>
        if(tag.equals("Include")) {
            String uri = attrs.getValue("URI");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = sig.getLastTimestampInfo();
                IncludeInfo inc = new IncludeInfo(uri);
                ts.addIncludeInfo(inc);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <CompleteCertificateRefs>
        if(tag.equals("CompleteCertificateRefs")) {
            String Target = attrs.getValue("Target");
            try {
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteCertificateRefs crefs =
                        new CompleteCertificateRefs();
                up.setCompleteCertificateRefs(crefs);
                crefs.setUnsignedProperties(up);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <CompleteRevocationRefs>
        if(tag.equals("CompleteRevocationRefs")) {
            try {
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteRevocationRefs rrefs = new CompleteRevocationRefs();
                up.setCompleteRevocationRefs(rrefs);
                rrefs.setUnsignedProperties(up);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <OCSPIdentifier>
        if(tag.equals("OCSPIdentifier")) {
            String URI = attrs.getValue("URI");
            try {
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                OcspRef orf = rrefs.getLastOcspRef();
                orf.setUri(URI);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <SignaturePolicyIdentifier>
        if(tag.equals("SignaturePolicyIdentifier")) {
            try {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                SignaturePolicyIdentifier spid = sp.getSignaturePolicyIdentifier();
                if(spid == null) {
                    spid = new SignaturePolicyIdentifier(null);
                    sp.setSignaturePolicyIdentifier(spid);
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <SignaturePolicyId>
        if(tag.equals("SignaturePolicyId")) {
            try {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                SignaturePolicyIdentifier spid = sp.getSignaturePolicyIdentifier();
                if(spid == null) {
                    spid = new SignaturePolicyIdentifier(null);
                    sp.setSignaturePolicyIdentifier(spid);
                }
                SignaturePolicyId spi = spid.getSignaturePolicyId();
                if(spi == null) {
                    spi = new SignaturePolicyId(null);
                    spid.setSignaturePolicyId(spi);
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <SigPolicyId>
        // cannot handle alone because we need mandatory Identifier value
        // <Identifier>
        if(tag.equals("Identifier")) {
            try {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                SignaturePolicyIdentifier spid = sp.getSignaturePolicyIdentifier();
                if(spid == null) {
                    spid = new SignaturePolicyIdentifier(null);
                    sp.setSignaturePolicyIdentifier(spid);
                }
                SignaturePolicyId spi = spid.getSignaturePolicyId();
                if(spi == null) {
                    spi = new SignaturePolicyId(null);
                    spid.setSignaturePolicyId(spi);
                }
                String sQualifier = attrs.getValue("Qualifier");
                Identifier id = new Identifier(sQualifier);
                ObjectIdentifier oi = spi.getSigPolicyId();
                if(oi == null)
                    oi = new ObjectIdentifier(id);
                else
                    oi.setIdentifier(id);
                spi.setSigPolicyId(oi);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <SigPolicyQualifier>
        if(tag.equals("SigPolicyQualifier")) {
            try {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                SignaturePolicyIdentifier spid = sp.getSignaturePolicyIdentifier();
                if(spid == null) {
                    spid = new SignaturePolicyIdentifier(null);
                    sp.setSignaturePolicyIdentifier(spid);
                }
                SignaturePolicyId spi = spid.getSignaturePolicyId();
                if(spi == null) {
                    spi = new SignaturePolicyId(null);
                    spid.setSignaturePolicyId(spi);
                }
                SigPolicyQualifier spq = new SigPolicyQualifier();
                spi.addSigPolicyQualifier(spq);
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }

        // <DataObjectFormat>
        if(tag.equals("DataObjectFormat")) {
            Signature sig = getLastSignature();
            try {
                if(sig != null) {
                    SignedProperties sp = sig.getSignedProperties();
                    if(sp != null) {
                        SignedDataObjectProperties sdps = sp.getSignedDataObjectProperties();
                        if(sdps == null) {
                            sdps = new SignedDataObjectProperties();
                            sp.setSignedDataObjectProperties(sdps);
                        }
                        String sObjectReference = attrs.getValue("ObjectReference");
                        DataObjectFormat dof = new DataObjectFormat(sObjectReference);
                        sdps.addDataObjectFormat(dof);
                    }
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // <NonceAlgorithm> - give error?
        if(tag.equals("NonceAlgorithm")) {

        }
        // the following stuff is ignored in collect mode
        // because it can only be the content of a higher element
        if(m_nCollectMode == 0) {
            // <SignedDoc>
            if(tag.equals("SignedDoc")) {
                String format = null, version = null;
                for(int i = 0; i < attrs.getLength(); i++) {
                    String key = attrs.getQName(i);
                    if(key.equals("format"))
                        format = attrs.getValue(i);
                    if(key.equals("version"))
                        version = attrs.getValue(i);
                }
                try {
                    m_doc = new SignedDoc();
                    m_doc.setFormat(format);
                    m_doc.setVersion(version);
                    if(format != null && (format.equals(SignedDoc.FORMAT_SK_XML) || format.equals(SignedDoc.FORMAT_DIGIDOC_XML))) {
                        m_doc.setProfile(SignedDoc.BDOC_PROFILE_TM); // in ddoc format we used only TM
                    }
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            // <Signature>
			/*if(qName.equals("Signature")) {
				String Id = attrs.getValue("Id");
				try {
					Signature sig = new Signature(m_doc);
					if(Id != null)
						sig.setId(Id);
					m_doc.addSignature(sig);
				} catch (DigiDocException ex) {
					handleSAXError(ex);
				}
			}*/
            // <KeyInfo>
            if(tag.equals("KeyInfo")) {
                try {
                    KeyInfo ki = new KeyInfo();
                    String Id = attrs.getValue("Id");
                    if(Id != null)
                        ki.setId(Id);
                    Signature sig = getLastSignature();
                    sig.setKeyInfo(ki);
                    ki.setSignature(sig);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            // <UnsignedProperties>
            if(tag.equals("UnsignedProperties")) {
                String Target = attrs.getValue("Target");
                try {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = new UnsignedProperties(sig);
                    sig.setUnsignedProperties(up);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            // <EncapsulatedOCSPValue>
            if(tag.equals("EncapsulatedOCSPValue")) {
                String Id = attrs.getValue("Id");
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                Notary not = new Notary();
                if(Id != null)
                    not.setId(Id);
                not.setId(Id);
                up.addNotary(not);
                if(sig.getProfile() == null &&
                        (m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
                                m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)))
                    sig.setProfile(SignedDoc.BDOC_PROFILE_TM);
            }
        } // if(m_nCollectMode == 0)
    }

    private static final String xmlnsEtsi = "http://uri.etsi.org/01903/v1.3.2#";
    private static final String xmlnsDs = "http://www.w3.org/2000/09/xmldsig#";
    private static final String xmlnsAsic = "http://uri.etsi.org/02918/v1.2.1#";
    //private static final String xmlnsNonce = "http://www.sk.ee/repository/NonceAlgorithm";

    private TreeSet collectNamespaces(String sCanInfo, TreeSet tsOtherAttr)
    {
        TreeSet ts = new TreeSet();
        // find element header
        int p1 = -1, p2 = -1;
        p1 = sCanInfo.indexOf('>');
        if(p1 != -1) {
            String sHdr = sCanInfo.substring(0, p1);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Header: " + sHdr);
            String[] toks = sHdr.split(" ");
            for(int i = 0; (toks != null) && (i < toks.length); i++) {
                String tok = toks[i];
                if(tok != null && tok.trim().length() > 0 && tok.charAt(0) != '<') {
                    if(tok.indexOf("xmlns") != -1)
                        ts.add(tok);
                    else
                        tsOtherAttr.add(tok);
                }
            }
        }
        return ts;
    }

    private void addNamespaceIfMissing(TreeSet ts, String ns, String pref)
    {
        boolean bF = false;
        Iterator iNs = ts.iterator();
        while(iNs.hasNext()) {
            String s = (String)iNs.next();
            if(s != null && s.indexOf(ns) != -1) {
                bF = true;
                break;
            }
        }
        if(!bF) {
            StringBuffer sb = new StringBuffer("xmlns");
            if(pref != null) {
                sb.append(":");
                sb.append(pref);
            }
            sb.append("=\"");
            sb.append(ns);
            sb.append("\"");
            ts.add(sb.toString());
        }
    }

    private String getPrefOfNs(String ns)
    {
        if(ns.indexOf(xmlnsDs) != -1) return m_nsDsPref;
        if(ns.indexOf(xmlnsEtsi) != -1) return m_nsXadesPref;
        if(ns.indexOf(xmlnsAsic) != -1) return m_nsAsicPref;
        return null;
    }

    private byte[] addNamespaces(byte[] bCanInfo, boolean bDsNs, boolean bEtsiNs,
                                 String dsNsPref, String xadesNsPref, boolean bAsicNs, String asicPref)
    {
        byte[] bInfo = bCanInfo;
        try {
            String s1 = new String(bCanInfo, "UTF-8");
            if(m_logger.isDebugEnabled())
                m_logger.debug("Input xml:\n------\n" + s1 + "\n------\n");
            TreeSet tsOtherAttr = new TreeSet();
            TreeSet tsNs = collectNamespaces(s1, tsOtherAttr);
            Iterator iNs = tsNs.iterator();
            while(iNs.hasNext()) {
                String s = (String)iNs.next();
                m_logger.debug("Has ns: " + s);
            }
            iNs = tsOtherAttr.iterator();
            while(iNs.hasNext()) {
                String s = (String)iNs.next();
                m_logger.debug("Other attr: " + s);
            }
            if(bDsNs)
                addNamespaceIfMissing(tsNs, xmlnsDs, dsNsPref);
            if(bEtsiNs)
                addNamespaceIfMissing(tsNs, xmlnsEtsi, xadesNsPref);
            if(bAsicNs)
                addNamespaceIfMissing(tsNs, xmlnsAsic, asicPref);
            iNs = tsNs.iterator();
            while(iNs.hasNext()) {
                String s = (String)iNs.next();
                m_logger.debug("Now has ns: " + s);
            }
            // put back in header
            int p1 = s1.indexOf(' ');
            int p2 = s1.indexOf('>');
            if(p1 > p2) p1 = p2; // if <SignedInfo> has no atributes
            String sRest = s1.substring(p2);
            StringBuffer sb = new StringBuffer();
            sb.append(s1.substring(0, p1));
            iNs = tsNs.iterator();
            while(iNs.hasNext()) {
                sb.append(" ");
                String s = (String)iNs.next();
                sb.append(s);
            }
            iNs = tsOtherAttr.iterator();
            while(iNs.hasNext()) {
                sb.append(" ");
                String s = (String)iNs.next();
                sb.append(s);
            }
            sb.append(sRest);
            bInfo = sb.toString().getBytes("UTF-8");
            if(m_logger.isDebugEnabled())
                m_logger.debug("Modified xml:\n------\n" + sb.toString() + "\n------\n");
        } catch(Exception ex) {
            m_logger.error("Error adding namespaces: " + ex);
        }
        return bInfo; // default is to return original content
    }

    private byte[] addNamespaceOnChildElems(byte[] bCanInfo, String nsPref, String nsUri)
    {
        byte[] bInfo = bCanInfo;
        try {
            String s1 = new String(bCanInfo, "UTF-8");
            if(m_logger.isDebugEnabled())
                m_logger.debug("AddChildNs: " + nsPref + "=" + nsUri + " Input xml:\n------\n" + s1 + "\n------\n");
            // find boundarys of root elem
            int p1 = s1.indexOf('>')+1;
            int p2 = s1.lastIndexOf('<');
            String sRest = s1.substring(p2);
            StringBuffer sb = new StringBuffer();
            sb.append(s1.substring(0, p1));
            int p3 = p1, p4 = 0, p5 = 0, p6 = 0;
            do {
                boolean bCopy = true;
                p4 = s1.indexOf('<', p3);
                // possible whitespace
                if(p4 > p3+1)
                    sb.append(s1.substring(p3, p4));
                p3 = p4;
                p4 = s1.indexOf('>', p3) + 1;
                if(s1.charAt(p3) == '<' && s1.charAt(p3+1) != '/') {
                    p5 = s1.indexOf(':', p3);
                    if(p5 > p3 && p5 < p4) {
                        String pref = s1.substring(p3+1, p5);
                        if(pref != null && pref.equals(nsPref)) {
                            p6 = s1.indexOf(' ', p5);
                            if(p6 > p4)
                                p6 = p4 - 1;
                            sb.append(s1.substring(p3, p6));
                            sb.append(" xmlns:");
                            sb.append(nsPref);
                            sb.append("=\"");
                            sb.append(nsUri);
                            sb.append("\"");
                            bCopy = false;
                            sb.append(s1.substring(p6, p4));
                        }
                    }
                }
                if(bCopy)
                    sb.append(s1.substring(p3, p4));
                if(p4 > 0 && p4 < p2)
                    p3 = p4;
            } while (p4 > 0 && p4 < p2);
            sb.append(sRest);
            bInfo = sb.toString().getBytes("UTF-8");
            if(m_logger.isDebugEnabled())
                m_logger.debug("Modified xml:\n------\n" + sb.toString() + "\n------\n");
        } catch(Exception ex) {
            m_logger.error("Error adding namespaces: " + ex);
        }
        return bInfo; // default is to return original content
    }

    /**
     * End Element handler
     * @param namespaceURI namespace URI
     * @param lName local name
     * @param qName qualified name
     */
    public void endElement(String namespaceURI, String sName, String qName)
            throws SAXException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("End Element: " + qName + " collect: " + m_nCollectMode);
        // remove last tag from stack
        String tag = qName;
        String nsPref = null;
        if(tag.indexOf(':') != -1) {
            tag = qName.substring(qName.indexOf(':') + 1);
            nsPref = qName.substring(0, qName.indexOf(':'));
        }
        if(m_elemCurrent != null)
            m_elemCurrent = m_elemCurrent.getParent();
        String currTag = (String) m_tags.pop();
        // collect SAX event data to original XML data
        // for <DataFile> we don't collect the begin and
        // end tags unless this an embedded <DataFile>
        StringBuffer sb = null;
        if (m_nCollectMode > 0
                && (!tag.equals("DataFile") || m_nCollectMode > 1)) {
            sb = new StringBuffer();
            sb.append("</");
            sb.append(qName);
            sb.append(">");
        }
        if (m_sbCollectSignature != null) {
            m_sbCollectSignature.append("</");
            m_sbCollectSignature.append(qName);
            m_sbCollectSignature.append(">");
        }
        // if we do cache in mem
        if(m_sbCollectChars != null && sb != null)
            m_sbCollectChars.append(sb.toString());

        // </DataFile>
        if(tag.equals("DataFile")) {
            m_nCollectMode--;
            if (m_nCollectMode == 0) {
                // close DataFile cache if necessary
                try {
                    if(m_dfCacheOutStream != null) {
                        if(sb != null)
                            m_dfCacheOutStream.write(ConvertUtils.str2data(sb.toString()));
                        m_dfCacheOutStream.close();
                        m_dfCacheOutStream = null;
                    }
                } catch (IOException ex) {
                    handleSAXError(ex);
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }

                DataFile df = m_doc.getLastDataFile();
                if(df != null && df.getContentType().equals(DataFile.CONTENT_EMBEDDED_BASE64)) {
                    try {
                        if(m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                            String sDf = null;
                            if(m_sbCollectChars != null) {
                                sDf = m_sbCollectChars.toString();
                                m_sbCollectChars = null;
                            } else if(df.getDfCacheFile() != null) {
                                byte[] data = null;
                                try {
                                    data = SignedDoc.readFile(df.getDfCacheFile());
                                    sDf = new String(data);
                                } catch(Exception ex) {
                                    m_logger.error("Error reading cache file: " + df.getDfCacheFile() + " - " + ex);
                                }
                            }
                            if(sDf != null) {
                                byte[] bDf = Base64Util.decode(sDf);
                                updateDigest(bDf);
                            }
                            df.setDigest(getDigest());
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("Digest: " + df.getId() + " - " + Base64Util.encode(df.getDigest()) + " size: " + df.getSize());
                        } else {
                            long nSize = df.getSize();
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("DF: " + df.getId() + " cache-file: " + df.getDfCacheFile());
                            if(df.getDfCacheFile() == null) {
                                byte[] b = Base64Util.decode(m_sbCollectChars.toString());
                                if(m_logger.isDebugEnabled())
                                    m_logger.debug("DF: " + df.getId() + " orig-size: " + nSize + " new size: " + b.length);
                                if(b != null && nSize == 0) nSize = b.length;
                                df.setBodyAsData(ConvertUtils.str2data(m_sbCollectChars.toString(), "UTF-8"), true, nSize);
                            }
                            // calc digest over end tag
                            updateDigest("</DataFile>".getBytes());
                            //df.setDigestType(SignedDoc.SHA1_DIGEST_TYPE);
                            df.setDigest(getDigest());
                            //df.setDigestValue(df.getDigest());
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("Digest: " + df.getId() + " - " + Base64Util.encode(df.getDigest()) + " size: " + df.getSize());
                        }
                        if(m_altDigest != null) {
                            //calc digest over end tag
                            updateAltDigest(ConvertUtils.str2data("</DataFile>"));
                            //df.setDigestType(SignedDoc.SHA1_DIGEST_TYPE);
                            df.setAltDigest(getAltDigest());
                            //df.setDigestValue(df.getDigest());
                        }
                        m_sbCollectChars = null; // stop collecting
                    } catch (DigiDocException ex) {
                        handleSAXError(ex);
                    }
                    // this would throw away whitespace so calculate digest before it
                    //df.setBody(Base64Util.decode(m_sbCollectChars.toString()));
                }
                m_bCollectDigest = false;
            }
        }
        // </SignedInfo>
        if(tag.equals("SignedInfo")) {
            if(m_nCollectMode > 0) m_nCollectMode--;
            // calculate digest over the original
            // XML form of SignedInfo block and save it
            try {
                Signature sig = getLastSignature();
                SignedInfo si = sig.getSignedInfo();
                String sSigInf = m_sbCollectChars.toString();
                if(m_logger.isDebugEnabled())
                    m_logger.debug("SigInf:\n------\n" + sSigInf + "\n------\n");
                //debugWriteFile("SigInfo1.xml", m_sbCollectChars.toString());
                byte[] bCanSI = null;
                if(m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                    bCanSI = sSigInf.getBytes();
                } else {
                    CanonicalizationFactory canFac = ConfigManager.instance().getCanonicalizationFactory();
                    if(si.getCanonicalizationMethod().equals(SignedDoc.CANONICALIZATION_METHOD_2010_10_EXC))
                        bCanSI = canFac.canonicalize(ConvertUtils.str2data(sSigInf, "UTF-8"), SignedDoc.CANONICALIZATION_METHOD_2010_10_EXC);
                    else
                        bCanSI = canFac.canonicalize(ConvertUtils.str2data(sSigInf, "UTF-8"), SignedDoc.CANONICALIZATION_METHOD_20010315);
                }
                si.setOrigDigest(SignedDoc.digestOfType(bCanSI,
                        (m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC) ?
                                SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE)));
                if(m_logger.isDebugEnabled())
                    m_logger.debug("SigInf:\n------\n" + new String(bCanSI) + "\n------\nHASH: " + Base64Util.encode(si.getOrigDigest()));
                if(m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC) /*||
						m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
						m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)*/) {
                    boolean bEtsiNs = false, bAsicNs = false;
                    if(m_nsXadesPref != null && m_nsXadesPref.length() > 0)
                        bEtsiNs = true;
                    if(m_nsAsicPref != null && m_nsAsicPref.length() > 0)
                        bAsicNs = true;
                    if(si.getCanonicalizationMethod().equals(SignedDoc.CANONICALIZATION_METHOD_2010_10_EXC)) {
                        bAsicNs = false;
                    }
                    bCanSI = addNamespaces(bCanSI, true, bEtsiNs, m_nsDsPref, m_nsXadesPref, bAsicNs, m_nsAsicPref);
                    si.setOrigXml(bCanSI);
                    String sDigType = ConfigManager.sigMeth2Type(si.getSignatureMethod());
                    if(sDigType != null)
                        si.setOrigDigest(SignedDoc.digestOfType(bCanSI, sDigType));
                    else
                        throw new DigiDocException(DigiDocException.ERR_SIGNATURE_METHOD, "Invalid signature method: " + si.getSignatureMethod(), null);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("\nHASH: " + Base64Util.encode(si.getOrigDigest()));
                }

                m_sbCollectChars = null; // stop collecting
                //debugWriteFile("SigInfo2.xml", si.toString());
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </SignedProperties>
        if(tag.equals("SignedProperties")) {
            if(m_nCollectMode > 0) m_nCollectMode--;
            // calculate digest over the original
            // XML form of SignedInfo block and save it
            //debugWriteFile("SigProps-orig.xml", m_sbCollectChars.toString());
            try {
                Signature sig = getLastSignature();
                SignedInfo si = sig.getSignedInfo();
                SignedProperties sp = sig.getSignedProperties();
                String sigProp = m_sbCollectChars.toString();
                //debugWriteFile("SigProp1.xml", sigProp);
                byte[] bSigProp = ConvertUtils.str2data(sigProp, "UTF-8");
                byte[] bDig0 = SignedDoc.digestOfType(bSigProp, SignedDoc.SHA1_DIGEST_TYPE);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("SigProp0:\n------\n" + sigProp + "\n------" + " len: " +
                            sigProp.length() + " sha1 HASH0: " + Base64Util.encode(bDig0));
                CanonicalizationFactory canFac = ConfigManager.instance().getCanonicalizationFactory();
                byte[] bCanProp = null;
                if(si.getCanonicalizationMethod().equals(SignedDoc.CANONICALIZATION_METHOD_2010_10_EXC))
                    bCanProp = canFac.canonicalize(bSigProp, SignedDoc.CANONICALIZATION_METHOD_2010_10_EXC);
                else
                    bCanProp = canFac.canonicalize(bSigProp, SignedDoc.CANONICALIZATION_METHOD_20010315);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("SigProp can:\n------\n" + new String(bCanProp, "UTF-8") + "\n------" + " len: " + bCanProp.length);
                if(m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                    boolean bNeedDsNs = false;
                    String st1 = new String(bCanProp);
                    if(st1.indexOf("<ds:X509IssuerName>") != -1) {
                        bNeedDsNs = true;
                    }
                    boolean bEtsiNs = false, bAsicNs = false;
                    if(m_nsXadesPref != null && m_nsXadesPref.length() > 0)
                        bEtsiNs = true;
                    if(m_nsAsicPref != null && m_nsAsicPref.length() > 0)
                        bAsicNs = true;
                    if(si.getCanonicalizationMethod().equals(SignedDoc.CANONICALIZATION_METHOD_2010_10_EXC)) {
                        bAsicNs = false;
                        bNeedDsNs = false;
                    }
                    bCanProp = addNamespaces(bCanProp, bNeedDsNs, bEtsiNs, m_nsDsPref, m_nsXadesPref, bAsicNs, m_nsAsicPref);
                    if(si.getCanonicalizationMethod().equals(SignedDoc.CANONICALIZATION_METHOD_2010_10_EXC))
                        bCanProp = addNamespaceOnChildElems(bCanProp, m_nsDsPref, xmlnsDs);
                    Reference spRef = sig.getSignedInfo().getReferenceForSignedProperties(sp);
                    if(spRef != null) {
                        String sDigType = ConfigManager.digAlg2Type(spRef.getDigestAlgorithm());
                        if(sDigType != null)
                            sp.setOrigDigest(SignedDoc.digestOfType(bCanProp, sDigType));
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("\nHASH: " + Base64Util.encode(sp.getOrigDigest()) + " REF-HASH: " + Base64Util.encode(spRef.getDigestValue()));
                    }
                }
                m_sbCollectChars = null; // stop collecting
                CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                if(cid != null) {
                    if(cid.getId() != null)
                        sp.setCertId(cid.getId());
                    else if(!sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3) &&
                            !m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                        sp.setCertId(sig.getId() + "-CERTINFO");
                    sp.setCertSerial(cid.getSerial());
                    sp.setCertDigestAlgorithm(cid.getDigestAlgorithm());
                    if(cid.getDigestValue() != null)
                        sp.setCertDigestValue(cid.getDigestValue());
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("CID: " + cid.getId() + " ser: " + cid.getSerial() + " alg: " + cid.getDigestAlgorithm());
                }
                if(m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
                        m_doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                    String sDigType1 = ConfigManager.digAlg2Type(sp.getCertDigestAlgorithm());
                    if(sDigType1 != null)
                        sp.setOrigDigest(SignedDoc.digestOfType(bCanProp, sDigType1));
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("SigProp2:\n------\n" + new String(bCanProp) + "\n------\n"  +
                                " len: " + bCanProp.length + " digtype: " + sDigType1 + " HASH: " + Base64Util.encode(sp.getOrigDigest()));
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            } catch(UnsupportedEncodingException ex) {
                handleSAXError(ex);
            }
        }
        // </SignatureValue>
        if(tag.equals("SignatureValue")) {
            if(m_nCollectMode > 0) m_nCollectMode--;
            m_strSigValTs = m_sbCollectChars.toString();
            m_sbCollectChars = null; // stop collecting
        }
        // </CompleteRevocationRefs>
        if(tag.equals("CompleteRevocationRefs")) {
            if(m_nCollectMode > 0) m_nCollectMode--;
            if(m_sbCollectChars != null)
                m_strSigAndRefsTs = m_strSigValTs + m_sbCollectChars.toString();
            m_sbCollectChars = null; // stop collecting
        }
        // </Signature>
        if(tag.equals("Signature")) {
            if (m_nCollectMode == 0) {
                if (m_logger.isDebugEnabled())
                    m_logger.debug("End collecting <Signature>");
                try {
                    Signature sig = getLastSignature();
                    //if (m_logger.isDebugEnabled())
                    //	m_logger.debug("Set sig content:\n---\n" + m_sbCollectSignature.toString() + "\n---\n");
                    if (m_sbCollectSignature != null && !sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                        sig.setOrigContent(ConvertUtils.str2data(m_sbCollectSignature.toString(), "UTF-8"));
                        //if (m_logger.isDebugEnabled())
                        //	m_logger.debug("SIG orig content set: " + sig.getId() + " len: " + ((sig.getOrigContent() == null) ? 0 : sig.getOrigContent().length));
                        //debugWriteFile("SIG-" + sig.getId() + ".txt", m_sbCollectSignature.toString());
                        m_sbCollectSignature = null; // reset collecting
                    }
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
        }
        // </XAdESSignatures>
        if(tag.equals("XAdESSignatures")) {
            if (m_nCollectMode == 0) {
                if (m_logger.isDebugEnabled())
                    m_logger.debug("End collecting <XAdESSignatures>");
                try {
                    Signature sig = getLastSignature();
                    //if (m_logger.isDebugEnabled())
                    //	m_logger.debug("Set sig content:\n---\n" + m_sbCollectSignature.toString() + "\n---\n");
                    if (m_sbCollectSignature != null) {
                        sig.setOrigContent(ConvertUtils.str2data(m_sbCollectSignature.toString(), "UTF-8"));
                        //if (m_logger.isDebugEnabled())
                        //	m_logger.debug("SIG orig content set: " + sig.getId() + " len: " + ((sig.getOrigContent() == null) ? 0 : sig.getOrigContent().length));
                        //debugWriteFile("SIG-" + sig.getId() + ".txt", m_sbCollectSignature.toString());
                        m_sbCollectSignature = null; // reset collecting
                    }
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
        }
        // </SignatureTimeStamp>
        if(tag.equals("SignatureTimeStamp")) {
            if (m_logger.isDebugEnabled())
                m_logger.debug("End collecting <SignatureTimeStamp>");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = sig.getTimestampInfoOfType(TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
                if(ts != null && m_strSigValTs != null) {
                    CanonicalizationFactory canFac = ConfigManager.instance().getCanonicalizationFactory();
                    byte[] bCanXml = canFac.canonicalize(ConvertUtils.str2data(m_strSigValTs, "UTF-8"),
                            SignedDoc.CANONICALIZATION_METHOD_20010315);
                    //TODO: other diges types for timestamps?
                    byte[] hash = SignedDoc.digest(bCanXml);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("SigValTS \n---\n" + new String(bCanXml) + "\n---\nHASH: " + Base64Util.encode(hash));
                    //debugWriteFile("SigProp2.xml", new String(bCanProp));
                    ts.setHash(hash);
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </SigAndRefsTimeStamp>
        if(tag.equals("SigAndRefsTimeStamp")) {
            if (m_logger.isDebugEnabled())
                m_logger.debug("End collecting <SigAndRefsTimeStamp>");
            try {
                Signature sig = getLastSignature();
                TimestampInfo ts = sig.getTimestampInfoOfType(TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS);
                if(ts != null && m_strSigAndRefsTs != null) {
                    String canXml = "<a>" + m_strSigAndRefsTs + "</a>";
                    CanonicalizationFactory canFac = ConfigManager.instance().getCanonicalizationFactory();
                    byte[] bCanXml = canFac.canonicalize(ConvertUtils.str2data(canXml, "UTF-8"),
                            SignedDoc.CANONICALIZATION_METHOD_20010315);
                    canXml = new String(bCanXml, "UTF-8");
                    canXml = canXml.substring(3, canXml.length() - 4);
                    //TODO: other diges types for timestamps?
                    byte[] hash = SignedDoc.digest(ConvertUtils.str2data(canXml, "UTF-8"));
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("SigAndRefsTimeStamp \n---\n" + canXml + "\n---\n" + Base64Util.encode(hash));
                    //debugWriteFile("SigProp2.xml", new String(bCanProp));
                    ts.setHash(hash);
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            } catch(Exception ex) {
                handleSAXError(ex);
            }
        }
        // the following stuff is used also in
        // collect mode level 1 because it can be part
        // of SignedInfo or SignedProperties
        if (m_nCollectMode == 1) {
            // </SigningTime>
            if(tag.equals("SigningTime")) {
                try {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    sp.setSigningTime(ConvertUtils.string2date(m_sbCollectItem.toString(), m_doc));
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    handleSAXError(ex);
                }
            }
            // </ClaimedRole>
            if(tag.equals("ClaimedRole")) {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                sp.addClaimedRole(m_sbCollectItem.toString());
                m_sbCollectItem = null; // stop collecting
            }
            // </City>
            if(tag.equals("City")) {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                spp.setCity(m_sbCollectItem.toString());
                m_sbCollectItem = null; // stop collecting
            }
            // </StateOrProvince>
            if(tag.equals("StateOrProvince")) {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                spp.setStateOrProvince(m_sbCollectItem.toString());
                m_sbCollectItem = null; // stop collecting
            }
            // </CountryName>
            if(tag.equals("CountryName")) {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                spp.setCountryName(m_sbCollectItem.toString());
                m_sbCollectItem = null; // stop collecting
            }
            // </PostalCode>
            if(tag.equals("PostalCode")) {
                Signature sig = getLastSignature();
                SignedProperties sp = sig.getSignedProperties();
                SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                spp.setPostalCode(m_sbCollectItem.toString());
                m_sbCollectItem = null; // stop collecting
            }

        } // level 1
        // the following is collected on any level
        // </DigestValue>
        if(tag.equals("DigestValue")) {
            try {
                if(m_tags.search("Reference") != -1) {
                    Signature sig = getLastSignature();
                    SignedInfo si = sig.getSignedInfo();
                    Reference ref = si.getLastReference();
                    ref.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                    m_sbCollectItem = null; // stop collecting
                } else if(m_tags.search("SigningCertificate") != -1) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    sp.setCertDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                    CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                    if(cid != null)
                        cid.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                    m_sbCollectItem = null; // stop collecting
                } else if(m_tags.search("CompleteCertificateRefs") != -1) {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteCertificateRefs crefs = up.getCompleteCertificateRefs();
                    CertID cid = crefs.getLastCertId();
                    if(cid != null)
                        cid.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("CertID: " + cid.getId() + " digest: " + m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                } else if(m_tags.search("CompleteRevocationRefs") != -1) {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    //if(rrefs.getDigestValue() == null) // ignore sub and root ca ocsp digests
                    OcspRef orf = rrefs.getLastOcspRef();
                    orf.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Revoc ref: " + m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                } else if(m_tags.search("SigPolicyHash") != -1) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignaturePolicyIdentifier spi = sp.getSignaturePolicyIdentifier();
                    SignaturePolicyId sppi = spi.getSignaturePolicyId();
                    sppi.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("SignaturePolicyId hash: " + m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
            } catch(DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </IssuerSerial>
        if(tag.equals("IssuerSerial") && m_doc != null
                && !m_doc.getVersion().equals(SignedDoc.VERSION_1_3)
                && !m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            try {
                Signature sig = getLastSignature();
                CertID cid = sig.getLastCertId();
                if(m_logger.isDebugEnabled())
                    m_logger.debug("X509SerialNumber 0: " + m_sbCollectItem.toString());
                if(cid != null)
                    cid.setSerial(ConvertUtils.string2bigint(m_sbCollectItem.toString()));
                m_sbCollectItem = null; // stop collecting
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </X509SerialNumber>
        if(tag.equals("X509SerialNumber") && m_doc != null
                && (m_doc.getVersion().equals(SignedDoc.VERSION_1_3)
                || m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC))) {
            try {
                Signature sig = getLastSignature();
                CertID cid = sig.getLastCertId();
                if(m_logger.isDebugEnabled())
                    m_logger.debug("X509SerialNumber: " + m_sbCollectItem.toString());
                if(cid != null)
                    cid.setSerial(ConvertUtils.string2bigint(m_sbCollectItem.toString()));
                if(m_logger.isDebugEnabled())
                    m_logger.debug("X509SerialNumber: " + cid.getSerial() + " type: " + cid.getType());
                m_sbCollectItem = null; // stop collecting
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </X509IssuerName>
        if(tag.equals("X509IssuerName") && m_doc != null
                && (m_doc.getVersion().equals(SignedDoc.VERSION_1_3)
                || m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC))) {
            try {
                Signature sig = getLastSignature();
                CertID cid = sig.getLastCertId();
                String s = m_sbCollectItem.toString();
                if(cid != null)
                    cid.setIssuer(s);
                if(m_logger.isDebugEnabled() && cid != null)
                    m_logger.debug("X509IssuerName: " + s + " type: " + cid.getType() + " nr: " + cid.getSerial());
                m_sbCollectItem = null; // stop collecting
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        //</EncapsulatedTimeStamp>
        if(tag.equals("EncapsulatedTimeStamp")) {
            Signature sig = getLastSignature();
            TimestampInfo ts = sig.getLastTimestampInfo();
            try {
                //ts.setTimeStampToken(new TimeStampToken(new CMSSignedData(Base64Util.decode(m_sbCollectItem.toString()))));
                BouncyCastleTimestampFactory tfac = new BouncyCastleTimestampFactory();
                ts.setTimeStampToken(tfac.readTsTok(Base64Util.decode(m_sbCollectItem.toString())));
                if(m_logger.isDebugEnabled() && ts != null)
                    m_logger.debug("TS: " + ts.getId() + " type: " + ts.getType() + " time: " + ts.getTime() + " digest: " + Base64Util.encode(ts.getMessageImprint()));
            } catch(Exception ex) {
                handleSAXError(new DigiDocException(DigiDocException.ERR_TIMESTAMP_RESP, "Invalid timestamp token", ex));
            }
            m_sbCollectItem = null; // stop collecting
        }
        // </ResponderID>
        if(tag.equals("ResponderID")) {
            try {
                if(!m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("ResponderID: " + m_sbCollectItem.toString());
                    OcspRef orf = rrefs.getLastOcspRef();
                    orf.setResponderId(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </ByName>
        if(tag.equals("ByName")) {
            try {
                if(m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("ResponderID by-name: " + m_sbCollectItem.toString());
                    OcspRef orf = rrefs.getLastOcspRef();
                    orf.setResponderId(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }

        // </ProducedAt>
        if(tag.equals("ProducedAt")) {
            try {
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                OcspRef orf = rrefs.getLastOcspRef();
                orf.setProducedAt(ConvertUtils.string2date(m_sbCollectItem.toString(), m_doc));
                m_sbCollectItem = null; // stop collecting
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }

        // the following stuff is ignored in collect mode
        // because it can only be the content of a higher element
        //if (m_nCollectMode == 0) {
        // </SignatureValue>
        if(tag.equals("SignatureValue")) {
            try {
                Signature sig = getLastSignature();
                SignatureValue sv = sig.getSignatureValue();
                //debugWriteFile("SigVal.txt", m_sbCollectItem.toString());
                if(m_sbCollectItem != null && m_sbCollectItem.length() > 0)
                    sig.setSignatureValue(Base64Util.decode(m_sbCollectItem.toString().trim()));
                //sv.setValue(Base64Util.decode(m_sbCollectItem.toString().trim()));
                if(m_logger.isDebugEnabled())
                    m_logger.debug("SIGVAL mode: " + m_nCollectMode + ":\n--\n" + (m_sbCollectItem != null ? m_sbCollectItem.toString() : "NULL") +
                            "\n---\n len: " + ((sv.getValue() != null) ? sv.getValue().length : 0));
                m_sbCollectItem = null; // stop collecting
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </X509Certificate>
        if(tag.equals("X509Certificate")) {
            try {
                Signature sig = getLastSignature();
                CertValue cval = sig.getLastCertValue();
                cval.setCert(SignedDoc.readCertificate(Base64Util.decode(m_sbCollectItem.toString())));
                m_sbCollectItem = null; // stop collecting
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </EncapsulatedX509Certificate>
        if(tag.equals("EncapsulatedX509Certificate")) {
            try {
                Signature sig = getLastSignature();
                CertValue cval = sig.getLastCertValue();
                cval.setCert(SignedDoc.readCertificate(Base64Util.decode(m_sbCollectItem.toString())));
                m_sbCollectItem = null; // stop collecting
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }
        // </EncapsulatedOCSPValue>
        if(tag.equals("EncapsulatedOCSPValue")) {
            try {
                Signature sig = getLastSignature();
                // first we have to find correct certid and certvalue types
                findCertIDandCertValueTypes(sig);
                UnsignedProperties up = sig.getUnsignedProperties();
                Notary not = up.getLastNotary();
                //if(m_logger.isDebugEnabled())
                //	m_logger.debug("Notary: " + not.getId() + " resp: " + m_sbCollectItem.toString());
                not.setOcspResponseData(Base64Util.decode(m_sbCollectItem.toString()));
                NotaryFactory notFac = ConfigManager.instance().getNotaryFactory();
                notFac.parseAndVerifyResponse(sig, not);
                // in 1.1 we had bad OCPS digest
                if (m_doc != null && m_doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) && m_doc.getVersion().equals(SignedDoc.VERSION_1_1)) {
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    OcspRef orf = rrefs.getLastOcspRef();
                    orf.setDigestValue(SignedDoc.digestOfType(not.getOcspResponseData(),
                            (m_doc.getFormat().equals(SignedDoc.FORMAT_BDOC) ?
                                    SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE)));
                }
                m_sbCollectItem = null; // stop collecting
            } catch (Exception ex) {
                handleSAXError(ex);
            }
        }
        // bdoc 2.0
        // </Identifier>
        if(tag.equals("Identifier")) {
            //try {
            Signature sig = getLastSignature();
            if(sig != null) {
                SignedProperties sp = sig.getSignedProperties();
                if(sp != null) {
                    SignaturePolicyIdentifier spid = sp.getSignaturePolicyIdentifier();
                    if(spid != null) {
                        SignaturePolicyId spi = spid.getSignaturePolicyId();
                        ObjectIdentifier oi = spi.getSigPolicyId();
                        if(oi != null) {
                            Identifier id = oi.getIdentifier();
                            id.setUri(m_sbCollectItem.toString().trim());
                            if(oi.getIdentifier().getUri().equals(DigiDocGenFactory.BDOC_210_OID)) {
                                try {
                                    m_doc.setVersion(SignedDoc.BDOC_VERSION_2_1);
                                } catch(Exception ex) {
                                    m_logger.error("Error setting 2.1 ver: " + ex);
                                }
                            }
                        }
                    }
                }
            }
            m_sbCollectItem = null; // stop collecting
			/*} catch (DigiDocException ex) {
				handleSAXError(ex);
			}*/
        }
        // </SPURI>
        if(tag.equals("SPURI")) {
            //try {
            Signature sig = getLastSignature();
            if(sig != null) {
                SignedProperties sp = sig.getSignedProperties();
                if(sp != null) {
                    SignaturePolicyIdentifier spid = sp.getSignaturePolicyIdentifier();
                    if(spid != null) {
                        SignaturePolicyId spi = spid.getSignaturePolicyId();
                        if(spi != null)
                            spi.addSigPolicyQualifier(new SpUri(m_sbCollectItem.toString().trim()));
                    }
                }
            }
            m_sbCollectItem = null; // stop collecting
			/*} catch (DigiDocException ex) {
				handleSAXError(ex);
			}*/
        }
        // </MimeType>
        if(tag.equals("MimeType")) {
            try {
                Signature sig = getLastSignature();
                if(sig != null) {
                    SignedProperties sp = sig.getSignedProperties();
                    if(sp != null) {
                        SignedDataObjectProperties sdps = sp.getSignedDataObjectProperties();
                        DataObjectFormat dof = sdps.getLastDataObjectFormat();
                        if(dof != null) {
                            dof.setMimeType(m_sbCollectItem.toString());
                            Reference ref = sig.getSignedInfo().getReferenceForDataObjectFormat(dof);
                            if(ref != null) {
                                for(int d = 0; d < sig.getSignedDoc().countDataFiles(); d++) {
                                    DataFile df = sig.getSignedDoc().getDataFile(d);
                                    if(df.getFileName() != null && df.getFileName().length() > 1 &&
                                            ref.getUri() != null && ref.getUri().length() > 1) {
                                        // normalize uri and filename
                                        String sFileName = df.getFileName();
                                        if(sFileName.charAt(0) == '/')
                                            sFileName = sFileName.substring(1);
                                        String sUri = ref.getUri();
                                        if(sUri.charAt(0) == '/')
                                            sUri = sUri.substring(1);
                                        if(sFileName.equals(sUri)) {
                                            df.setMimeType(m_sbCollectItem.toString());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                m_sbCollectItem = null; // stop collecting
            } catch (DigiDocException ex) {
                handleSAXError(ex);
            }
        }

        //} // if(m_nCollectMode == 0)
    }

    /**
     * SAX characters event handler
     * @param buf received bytes array
     * @param offset offset to the array
     * @param len length of data
     */
    public void characters(char buf[], int offset, int len)
            throws SAXException
    {
        String s = new String(buf, offset, len);
        // just collect the data since it could
        // be on many lines and be processed in many events
        if (s != null) {
            if (m_sbCollectItem != null) {
                m_sbCollectItem.append(s);
                //if(m_logger.isDebugEnabled())
                //	m_logger.debug("IN:\n---\n" + s + "\n---\nCollected:\n---\n" + m_sbCollectItem.toString() + "\n---\n");
            }
            if (m_sbCollectChars != null) {
                //m_sbCollectChars.append(s);
                if(m_logger.isDebugEnabled() && m_sbCollectChars.indexOf("SignedInfo") != -1)
                    m_logger.debug("IN: \'" + s + "\' escaped: \'" + ConvertUtils.escapeTextNode(s) + "\'");
                m_sbCollectChars.append(ConvertUtils.escapeTextNode(s));
            }
            if (m_sbCollectSignature != null)
                m_sbCollectSignature.append(ConvertUtils.escapeTextNode(s));
            if(m_digest != null && m_bCollectDigest)
                updateDigest(s.getBytes());
            if(m_altDigest != null && m_bCollectDigest)
                updateAltDigest(s.getBytes());
            try {
                if(m_dfCacheOutStream != null)
                    m_dfCacheOutStream.write(ConvertUtils.str2data(s));
            } catch(DigiDocException ex) {
                handleSAXError(ex);
            } catch(IOException ex) {
                handleSAXError(ex);
            }
        }
    }

}
