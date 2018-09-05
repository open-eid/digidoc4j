package org.digidoc4j.ddoc;

import org.digidoc4j.ddoc.utils.ConfigManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;

/**
 * Represents and XML-DSIG reference block
 * that referrs to a particular piece of
 * signed XML data and contains it's hash code.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class Reference implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** reference to parent SignedInfo object */
    private SignedInfo m_sigInfo;
    /** Id atribute value if set */
    private String m_id;
    /** URI to signed XML data */
    private String m_uri;
    /** selected digest algorithm */
    private String m_digestAlgorithm;
    /** digest data */
    private byte[] m_digestValue;
    /** transform algorithm */
    private String m_transformAlgorithm;
    /** type uri */
    private String m_type;
    private static Logger m_logger = LoggerFactory.getLogger(Reference.class);

    /**
     * Creates new Reference. Initializes
     * everything to null
     * @param sigInfo reference to parent SignedInfo object
     */
    public Reference(SignedInfo sigInfo)
    {
        m_sigInfo = sigInfo;
        m_uri = null;
        m_id = null;
        m_type = null;
        m_digestAlgorithm = null;
        m_digestValue = null;
        m_transformAlgorithm = null;
    }

    /**
     * Creates new Reference
     * @param sigInfo reference to parent SignedInfo object
     * @param uri reference uri pointing to signed XML data
     * @param algorithm sigest algorithm identifier
     * @param digest message digest data
     * @param transform transform algorithm
     * @throws DigiDocException for validation errors
     */
    public Reference(SignedInfo sigInfo, String uri, String algorithm,
                     byte[] digest, String transform)
            throws DigiDocException
    {
        m_sigInfo = sigInfo;
        setUri(uri);
        setDigestAlgorithm(algorithm);
        setDigestValue(digest);
        setTransformAlgorithm(transform);
    }

    /**
     * Creates new Reference
     * and initializes it with default
     * values from the DataFile
     * @param sigInfo reference to parent SignedInfo object
     * @param df DataFile object
     * @param digType digest type. Use null for default value
     * @throws DigiDocException for validation errors
     */
    public Reference(SignedInfo sigInfo, DataFile df, String digType)
            throws DigiDocException
    {
        m_sigInfo = sigInfo;
        String sDigType = digType;
        if(digType == null)
            sDigType = ConfigManager.instance().getDefaultDigestType(m_sigInfo.getSignature().getSignedDoc());
        String sDigAlg = ConfigManager.digType2Alg(sDigType);
        setDigestAlgorithm(sDigAlg);
        // BDOC or plain xades
        if(m_sigInfo.getSignature().getSignedDoc() != null &&
                m_sigInfo.getSignature().getSignedDoc().getFormat() != null &&
                m_sigInfo.getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) ) {
            String s = df.getFileName();
            int n1 = s.lastIndexOf(File.separator);
            if(n1 > 0 && n1 < s.length())
                s = s.substring(n1+1);
            if(m_sigInfo.getSignature().getSignedDoc().getVersion().equals(SignedDoc.BDOC_VERSION_2_1))
                setUri(s);
            else
                setUri("/" + s);
        } else { // digidoc
            if(df.getContentType().equals(DataFile.CONTENT_HASHCODE) ||
                    df.getContentType().equals(DataFile.CONTENT_EMBEDDED_BASE64)) {
                setUri("#" + df.getId());
            }
        }
        setDigestValue(df.getDigestValueOfType(sDigType));
    }

    /**
     * Accessor for sigInfo attribute
     * @return value of sigInfo attribute
     */
    public SignedInfo getSignedInfo() {
        return m_sigInfo;
    }

    /**
     * Mutator for sigInfo attribute
     * @param sigInfo new value for sigInfo attribute
     */
    public void setSignedInfo(SignedInfo sigInfo)
    {
        m_sigInfo = sigInfo;
    }

    /**
     * Creates new Reference
     * and initializes it with default
     * values from the SignedProperties
     * @param sigInfo reference to parent SignedInfo object
     * @param sp SignedProperties object
     * @param digType digest type. Use null for default value
     * @throws DigiDocException for validation errors
     */
    public Reference(SignedInfo sigInfo, SignedProperties sp, String digType)
            throws DigiDocException
    {
        m_sigInfo = sigInfo;
        String sDigType = digType;
        if(digType == null)
            sDigType = ConfigManager.instance().getDefaultDigestType(m_sigInfo.getSignature().getSignedDoc());
        String sDigAlg = ConfigManager.digType2Alg(sDigType);
        setDigestAlgorithm(sDigAlg);
        setUri(sp.getTarget() + "-SignedProperties");
        setDigestValue(sp.calculateDigest());
        setTransformAlgorithm(null);
    }


    /**
     * Accessor for uri attribute
     * @return value of uri attribute
     */
    public String getUri() {
        return m_uri;
    }

    /**
     * Mutator for uri attribute
     * @param str new value for uri attribute
     * @throws DigiDocException for validation errors
     */
    public void setUri(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateUri(str);
        if(ex != null)
            throw ex;
        m_uri = str;
    }

    /**
     * Helper method to validate a uri
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateUri(String str)
    {
        DigiDocException ex = null;
        // check the uri somehow ???
        if(str == null) {
            ex = new DigiDocException(DigiDocException.ERR_REFERENCE_URI,"URI does not exists", null);
        }
        return ex;
    }

    /**
     * Accessor for Id attribute
     * @return value of Id attribute
     */
    public String getId() {
        return m_id;
    }

    /**
     * Mutator for Id attribute
     * @param str new value for Id attribute
     */
    public void setId(String str)
    {
        m_id = str;
    }

    /**
     * Accessor for digestAlgorithm attribute
     * @return value of digestAlgorithm attribute
     */
    public String getDigestAlgorithm() {
        return m_digestAlgorithm;
    }

    /**
     * Mutator for digestAlgorithm attribute
     * @param str new value for digestAlgorithm attribute
     * @throws DigiDocException for validation errors
     */
    public void setDigestAlgorithm(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateDigestAlgorithm(str);
        if(ex != null)
            throw ex;
        m_digestAlgorithm = str;
    }

    /**
     * Helper method to validate a digest algorithm
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestAlgorithm(String str)
    {
        DigiDocException ex = null;
        if(str == null ||
                (!str.equals(SignedDoc.SHA1_DIGEST_ALGORITHM) &&
                        !str.equals(SignedDoc.SHA224_DIGEST_ALGORITHM) &&
                        !str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_1) &&
                        !str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_2) &&
                        !str.equals(SignedDoc.SHA512_DIGEST_ALGORITHM)))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM,
                    "Currently supports only SHA-1, SHA-256 or SHA-512 digest algorithm", null);
        return ex;
    }

    /**
     * Accessor for digestValue attribute
     * @return value of digestValue attribute
     */
    public byte[] getDigestValue() {
        return m_digestValue;
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
        m_digestValue = data;
    }

    /**
     * Helper method to validate a digest value
     * @param data input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestValue(byte[] data)
    {
        DigiDocException ex = null;
        if(data == null ||
                (data.length != SignedDoc.SHA1_DIGEST_LENGTH &&
                        data.length != SignedDoc.SHA224_DIGEST_LENGTH &&
                        data.length != SignedDoc.SHA256_DIGEST_LENGTH &&
                        data.length != SignedDoc.SHA512_DIGEST_LENGTH))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_LENGTH,
                    "Invalid digest length", null);
        return ex;
    }

    /**
     * Accessor for transformAlgorithm attribute
     * @return value of transformAlgorithm attribute
     */
    public String getTransformAlgorithm() {
        return m_transformAlgorithm;
    }

    /**
     * Mutator for transformAlgorithm attribute.
     * Currently supports only one transform which
     * has to be digidoc detatched document transform
     * or none at all.
     * @param str new value for transformAlgorithm attribute
     * @throws DigiDocException for validation errors
     */
    public void setTransformAlgorithm(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateTransformAlgorithm(str);
        if(ex != null)
            throw ex;
        m_transformAlgorithm = str;
    }

    /**
     * Helper method to validate a transform algorithm
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateTransformAlgorithm(String str)
    {
        DigiDocException ex = null;
        if(str != null && !str.equals(SignedDoc.DIGIDOC_DETATCHED_TRANSFORM) &&
                !str.equals(SignedDoc.TRANSFORM_20001026) && !str.equals(SignedDoc.ENVELOPED_TRANSFORM))
            ex = new DigiDocException(DigiDocException.ERR_TRANSFORM_ALGORITHM,
                    "Currently supports either no transforms or one detatched document transform", null);
        return ex;
    }

    /**
     * Accessor for Type attribute
     * @return value of Type attribute
     */
    public String getType() {
        return m_type;
    }

    /**
     * Mutator for Type attribute
     * @param str new value for Type attribute
     * @throws DigiDocException for validation errors
     */
    public void setType(String str)
    {
        m_type = str;
    }

    /**
     * Helper method to validate the whole
     * Reference object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateUri(m_uri);
        if(ex != null)
            errs.add(ex);
        ex = validateDigestAlgorithm(m_digestAlgorithm);
        if(ex != null)
            errs.add(ex);
        ex = validateDigestValue(m_digestValue);
        if(ex != null)
            errs.add(ex);
        ex = validateTransformAlgorithm(m_transformAlgorithm);
        if(ex != null)
            errs.add(ex);
        return errs;
    }


}