package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.Manifest;
import org.digidoc4j.ddoc.ManifestFileEntry;
import org.digidoc4j.ddoc.SignedDoc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * SAX implementation of BdocManifestParser
 * Provides methods for reading a manifest.xml file
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class BdocManifestParser extends DefaultHandler
{
    //private Stack m_tags;
    private SignedDoc m_sdoc;
    /** log4j logger */
    private Logger m_logger = null;

    public static final String  MIME_SIGNATURE_BDOC_BES = "signature/bdoc-1.0/BES";
    public static final String  MIME_SIGNATURE_BDOC_T = "signature/bdoc-1.1/T";
    public static final String  MIME_SIGNATURE_BDOC_CL = "signature/bdoc-1.1/C-L";
    public static final String  MIME_SIGNATURE_BDOC_TM = "signature/bdoc-1.0/TM";
    public static final String  MIME_SIGNATURE_BDOC_TS = "signature/bdoc-1.0/TS";
    public static final String  MIME_SIGNATURE_BDOC_TMA = "signature/bdoc-1.0/TM-A";
    public static final String  MIME_SIGNATURE_BDOC_TSA = "signature/bdoc-1.0/TS-A";

    /**
     * Constructor for BdocManifestParser
     * @param sdoc SignedDoc object
     */
    public BdocManifestParser(SignedDoc sdoc)
    {
        m_sdoc = sdoc;
        m_logger = LoggerFactory.getLogger(BdocManifestParser.class);
    }

    private InputStream removeDtd(InputStream is)
    {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] data = new byte[2048];
            int n;
            while((n = is.read(data)) > 0)
                bos.write(data, 0, n);
            data = bos.toByteArray();
            bos.close();
            String s = new String(data, "UTF-8");
            if(m_logger.isDebugEnabled())
                m_logger.debug("Manifest orig:\n------\n" + s + "\n------\n");
            data = null;
            int p1 = s.indexOf("<!DOCTYPE");
            int p2 = 0;
            if(p1 > 0) {
                p2 = s.indexOf(">", p1);
                if(p2 > 0) {
                    String s2 = s.substring(0, p1) + s.substring(p2+1);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Manifest no-dtd:\n------\n" + s2 + "\n------\n");
                    return new ByteArrayInputStream(s2.getBytes());
                }
            } else
                return new ByteArrayInputStream(s.getBytes("UTF-8"));
        } catch(Exception ex) {
            m_logger.error("Error removing dtd: " + ex);
        }
        return is;
    }

    /**
     * Reads in a manifest.xml file
     * @param is opened stream with manifest.xml data
     * The user must open and close it.
     * @return Manifest object if successfully parsed
     */
    public Manifest readManifest(InputStream is)
            throws DigiDocException
    {
        // Use an instance of ourselves as the SAX event handler
        BdocManifestParser handler = this;
        // Use the default (non-validating) parser
        SAXParserFactory factory = SAXParserFactory.newInstance();

        if(m_logger.isDebugEnabled())
            m_logger.debug("Start reading manifest.xml");
        try {
            factory.setValidating(false);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            //factory.setFeature("http://xml.org/sax/features/validation", false);
            //factory.setFeature("http://xml.org/sax/features/resolve-dtd-uris", false);
            SAXParser saxParser = factory.newSAXParser();
            InputStream is2 = removeDtd(is);
            saxParser.parse(is2, handler);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if(m_sdoc.getManifest() == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "This document is not in manifest.xml format", null);
        return m_sdoc.getManifest();
    }

    /**
     * Start Document handler
     */
    public void startDocument() throws SAXException {

    }

    /**
     * End Document handler
     */
    public void endDocument() throws SAXException {

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
        //m_tags.push(qName);
        String tag = qName;
        int p1 = tag.indexOf(':');
        if(p1 > 0)
            tag = qName.substring(p1+1);
        // <manifest>
        if(tag.equals("manifest")) {
            Manifest mf = new Manifest();
            m_sdoc.setManifest(mf);
        }
        // <file-entry>
        if(tag.equals("file-entry")) {
            String sType = null, sPath = null;
            for(int i = 0; i < attrs.getLength(); i++) {
                String key = attrs.getQName(i);
                p1 = key.indexOf(':');
                if(p1 > 0)
                    key = key.substring(p1+1);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("attr: " + key);
                if(key.equals("media-type")) {
                    sType = attrs.getValue(i);
                }
                if(key.equals("full-path")) {
                    sPath = attrs.getValue(i);
                }
            }
            if(m_logger.isDebugEnabled())
                m_logger.debug("Manif entry: " + sPath + " type: " + sType);
            ManifestFileEntry fe = new ManifestFileEntry(sType, sPath);
            m_sdoc.getManifest().addFileEntry(fe);
            try {
                if(sPath.equals("/")) { // signed doc entry
                    m_sdoc.setMimeType(sType);
                    m_sdoc.setFormat(SignedDoc.FORMAT_BDOC);
                    if(sType != null && sType.equals(SignedDoc.MIMET_FILE_CONTENT_10))
                        m_sdoc.setVersion(SignedDoc.VERSION_1_0);
                    if(sType != null && sType.equals(SignedDoc.MIMET_FILE_CONTENT_11))
                        m_sdoc.setVersion(SignedDoc.VERSION_1_1);
                    m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_BES); // default is weakest profile
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Sdoc: " + m_sdoc.getFormat() + " / " + m_sdoc.getVersion() + " / " + m_sdoc.getProfile());
                } else if(sPath.indexOf("signature") != -1) { // signature entry
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Find sig: " + sPath + " type: " + sType);
                    if(sType.startsWith(SAXDigiDocFactory.MIME_SIGNATURE_BDOC) &&
                            !sType.equals(MIME_SIGNATURE_BDOC_BES) &&
                            !sType.equals(MIME_SIGNATURE_BDOC_T) &&
                            !sType.equals(MIME_SIGNATURE_BDOC_CL) &&
                            !sType.equals(MIME_SIGNATURE_BDOC_TM) &&
                            !sType.equals(MIME_SIGNATURE_BDOC_TS) &&
                            !sType.equals(MIME_SIGNATURE_BDOC_TMA) &&
                            !sType.equals(MIME_SIGNATURE_BDOC_TSA) ) {
                        DigiDocException dex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                                "Invalid bdoc format: " + sPath, null);
                        SAXDigiDocException.handleException(dex); // report invalid signature format
                    }
                    String sigProfile = m_sdoc.findSignatureProfile(sPath);
                    if(sigProfile == null) {
                        if(sType.equals(MIME_SIGNATURE_BDOC_BES)) {
                            m_sdoc.addSignatureProfile(sPath, SignedDoc.BDOC_PROFILE_BES);
                            if(m_sdoc.getProfile() == null ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES)) // weakest profile to be set only if
                                m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_BES);
                        }
                        if(sType.equals(MIME_SIGNATURE_BDOC_T)) {
                            m_sdoc.addSignatureProfile(sPath, SignedDoc.BDOC_PROFILE_T);
                            if(m_sdoc.getProfile() == null ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_T))
                                m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_T);
                        }
                        if(sType.equals(MIME_SIGNATURE_BDOC_CL)) {
                            m_sdoc.addSignatureProfile(sPath, SignedDoc.BDOC_PROFILE_CL);
                            if(m_sdoc.getProfile() == null ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_T) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_CL))
                                m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_CL);
                        }
                        if(sType.equals(MIME_SIGNATURE_BDOC_TM)) {
                            m_sdoc.addSignatureProfile(sPath, SignedDoc.BDOC_PROFILE_TM);
                            if(m_sdoc.getProfile() == null ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_T) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_CL) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_TM))
                                m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_TM);
                        }
                        if(sType.equals(MIME_SIGNATURE_BDOC_TS)) {
                            m_sdoc.addSignatureProfile(sPath, SignedDoc.BDOC_PROFILE_TS);
                            if(m_sdoc.getProfile() == null ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_T) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_CL) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_TS))
                                m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_TS);
                        }
                        if(sType.equals(MIME_SIGNATURE_BDOC_TMA)) {
                            m_sdoc.addSignatureProfile(sPath, SignedDoc.BDOC_PROFILE_TMA);
                            if(m_sdoc.getProfile() == null ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_T) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_CL) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_TM) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_TMA))
                                m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_TMA);
                        }
                        if(sType.equals(MIME_SIGNATURE_BDOC_TSA)) {
                            m_sdoc.addSignatureProfile(sPath, SignedDoc.BDOC_PROFILE_TSA);
                            if(m_sdoc.getProfile() == null ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_T) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_CL) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_TS) ||
                                    m_sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_TSA))
                                m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_TSA);
                        }
                    }
                } else { // data file entry
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Manifest df: " + sPath);
                }
            } catch(DigiDocException ex) {
                SAXDigiDocException.handleException(ex);
            }
        }

    }

    private boolean isCorrectDataFilePath(String sPath)
    {
        if(sPath != null && sPath.length() > 0) {
            if(sPath.startsWith("/") ||
                    sPath.startsWith("..") ||
                    (sPath.length() > 3 && Character.isLetter(sPath.charAt(0)) &&
                            sPath.charAt(1) == ':' && sPath.charAt(2) == '\\'))
                return false;
            return true;
        }
        return false;
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
        //if(m_logger.isDebugEnabled())
        //	m_logger.debug("End Element: " + qName + " collect: " + m_nCollectMode);
        // remove last tag from stack
        //String currTag = (String)m_tags.pop();

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
		/*String s = new String(buf, offset, len);
        if (s != null) {
			if (m_sbCollectChars != null)
				m_sbCollectChars.append(s);
		}*/
    }
}
