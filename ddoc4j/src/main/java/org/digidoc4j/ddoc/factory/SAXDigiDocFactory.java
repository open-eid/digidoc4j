package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.*;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.ddoc.utils.ConvertUtils;
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
     * Reads in a DDoc file. One of fname or isSdoc must be given.
     * @param fname signed doc filename
     * @param isSdoc opened stream with DigiDoc data
     * The user must open and close it.
     * @param errs list of errors to fill with parsing errors. If given
     * then attempt is made to continue parsing on errors and return them in this list.
     * If not given (null) then the first error found will be thrown.
     * @return signed document object if successfully parsed
     */
    private SignedDoc readSignedDocOfType(String fname, InputStream isSdoc, List errs)
            throws DigiDocException
    {
        // Use an instance of ourselves as the SAX event handler
        SAXDigiDocFactory handler = this;
        m_errs = errs;
        DigiDocVerifyFactory.initProvider();
        SAXParserFactory factory = SAXParserFactory.newInstance();
        if(m_logger.isDebugEnabled())
            m_logger.debug("Start reading ddoc " + ((fname != null) ? "from file: " + fname : "from stream"));
        if(fname == null && isSdoc == null) {
            throw new DigiDocException(DigiDocException.ERR_READ_FILE, "No input file", null);
        }
        if(fname != null) {
            File inFile = new File(fname);
            if(!inFile.canRead() || inFile.length() == 0) {
                throw new DigiDocException(DigiDocException.ERR_READ_FILE, "Empty or unreadable input file", null);
            }
        }
        try {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            if(m_logger.isDebugEnabled())
                m_logger.debug("Reading ddoc: " + fname + " file: " + m_fileName);
            m_fileName = fname;
            SAXParser saxParser = factory.newSAXParser();
            if(fname != null)
                saxParser.parse(new SignatureInputStream(new FileInputStream(fname)), this);
            else if(isSdoc != null)
                saxParser.parse(new SignatureInputStream(isSdoc), this);
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
        }
        boolean bErrList = (errs != null);
        if(errs == null)
            errs = new ArrayList();
        if(m_doc == null) {
            m_logger.error("Error reading4: doc == null");
            handleError(new DigiDocException(DigiDocException.ERR_DIGIDOC_BADXML,
                    "This document is not in ddoc format", null));
        }
        if(!bErrList && errs.size() > 0) { // if error list was not used then we have to throw exception. So we will throw the first one since we can only do it once
            DigiDocException ex = (DigiDocException)errs.get(0);
            throw ex;
        }
        return m_doc;
    }



    /**
     * Reads in a DDoc file
     * @param fname filename
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(String fname)
            throws DigiDocException
    {
        return readSignedDocOfType(fname, null, null);
    }

    /**
     * Reads in a DDoc from stream.
     * @param is opened stream with DDoc data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     * @deprecated use readSignedDocFromStreamOfType(InputStream is, List lerr)
     */
    public SignedDoc readSignedDocFromStream(InputStream is)
            throws DigiDocException
    {
        return readSignedDocOfType(null, is, null);
    }

    /**
     * Reads in a DDoc file
     * @param fname filename
     * @param lerr list of errors to be filled. If not null then no exceptions are thrown
     * but returned in this array
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(String fname, List lerr)
            throws DigiDocException
    {
        return readSignedDocOfType(fname, null, lerr);
    }

    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * @param is opened stream with DigiDoc/BDOC data
     * The user must open and close it.
     * @param lerr list of errors to be filled. If not null then no exceptions are thrown
     * but returned in this array
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocFromStream(InputStream is, List lerr)
            throws DigiDocException
    {
        return readSignedDocOfType(null, is, lerr);
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
                (tag.equals("ResponderID")) ||
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
                        if(ContentType != null && ContentType.equals(DataFile.CONTENT_HASHCODE))
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
                            (m_doc.getVersion().equals(SignedDoc.VERSION_1_3)))
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
            // in case of ddoc-s try find existing signature.
            // to support libc++ buggy implementation with non-unique id atributes
            if(m_doc != null)
                sig = m_doc.findSignatureById(str1);
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
						sig.setProfile(SignedDoc.PROFILE_TM);*/
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
                        m_doc.setProfile(SignedDoc.PROFILE_TM); // in ddoc format we used only TM
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
                    sig.setProfile(SignedDoc.PROFILE_TM);
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
                                setDataFileBodyAsData(df);
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
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("DF: " + df.getId() + " cache-file: " + df.getDfCacheFile());
                            if(df.getDfCacheFile() == null) {
                                setDataFileBodyAsData(df);
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
                si.setOrigDigest(SignedDoc.digestOfType(bCanSI, SignedDoc.SHA1_DIGEST_TYPE));
                if(m_logger.isDebugEnabled())
                    m_logger.debug("SigInf:\n------\n" + new String(bCanSI) + "\n------\nHASH: " + Base64Util.encode(si.getOrigDigest()));

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
                m_sbCollectChars = null; // stop collecting
                CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                if(cid != null) {
                    if(cid.getId() != null)
                        sp.setCertId(cid.getId());
                    else if(!sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3))
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
                && !m_doc.getVersion().equals(SignedDoc.VERSION_1_3)) {
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
                && (m_doc.getVersion().equals(SignedDoc.VERSION_1_3))) {
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
                && (m_doc.getVersion().equals(SignedDoc.VERSION_1_3))) {
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
        // </ResponderID>
        if(tag.equals("ResponderID")) {
            try {
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                if(m_logger.isDebugEnabled())
                    m_logger.debug("ResponderID: " + m_sbCollectItem.toString());
                OcspRef orf = rrefs.getLastOcspRef();
                orf.setResponderId(m_sbCollectItem.toString());
                m_sbCollectItem = null; // stop collecting
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
                    orf.setDigestValue(SignedDoc.digestOfType(not.getOcspResponseData(), SignedDoc.SHA1_DIGEST_TYPE));
                }
                m_sbCollectItem = null; // stop collecting
            } catch (Exception ex) {
                handleSAXError(ex);
            }
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

    private void setDataFileBodyAsData(DataFile df) throws DigiDocException {
        long nSize = df.getSize();
        byte[] b = Base64Util.decode(m_sbCollectChars.toString());
        if(m_logger.isDebugEnabled())
            m_logger.debug("DF: " + df.getId() + " orig-size: " + nSize + " new size: " + b.length);
        if(nSize == 0) nSize = b.length;
        df.setBodyAsData(ConvertUtils.str2data(m_sbCollectChars.toString(), "UTF-8"), true, nSize);
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
