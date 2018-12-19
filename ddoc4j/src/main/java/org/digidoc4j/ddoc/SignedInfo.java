package org.digidoc4j.ddoc;

import org.digidoc4j.ddoc.factory.CanonicalizationFactory;
import org.digidoc4j.ddoc.factory.DigiDocXmlGenFactory;
import org.digidoc4j.ddoc.utils.ConfigManager;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;

/**
 * Represents an XML-DSIG SignedInfo block
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignedInfo implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** Id atribute value if set */
    private String m_id;
    /** reference to parent Signature object */
    private Signature m_signature;
    /** selected signature method */
    private String m_signatureMethod;
    /** selected canonicalization method */
    private String m_canonicalizationMethod;
    /** array of references */
    private ArrayList m_references;
    /** digest over the original bytes read from XML file  */
    private byte[] m_origDigest, m_origXml;

    /**
     * Creates new SignedInfo. Initializes everything to null.
     * @param sig parent Signature reference
     */
    public SignedInfo(Signature sig)
    {
        m_id = null;
        m_signature = sig;
        m_signatureMethod = null;
        m_canonicalizationMethod = null;
        m_references = null;
        m_origDigest = null;
        m_origXml = null;
    }

    /**
     * Creates new SignedInfo
     * @param sig parent Signature reference
     * @param signatureMethod signature method uri
     * @param canonicalizationMethod xml canonicalization method uri
     * throws DigiDocException
     */
    public SignedInfo(Signature sig, String signatureMethod, String canonicalizationMethod)
            throws DigiDocException
    {
        m_id = null;
        m_signature = sig;
        setSignatureMethod(signatureMethod);
        setCanonicalizationMethod(canonicalizationMethod);
        m_references = null;
        m_origDigest = null;
    }

    /**
     * Accessor for signature attribute
     * @return value of signature attribute
     */
    public Signature getSignature() {
        return m_signature;
    }

    /**
     * Mutator for signature attribute
     * @param sig new value for signature attribute
     */
    public void setSignature(Signature sig)
    {
        m_signature = sig;
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
     * Accessor for origDigest attribute
     * @return value of origDigest attribute
     */
    public byte[] getOrigDigest() {
        return m_origDigest;
    }

    /**
     * Mutator for origDigest attribute
     * @param str new value for origDigest attribute
     */
    public void setOrigDigest(byte[] data)
    {
        m_origDigest = data;
    }

    /**
     * Accessor for origXml attribute
     * @return value of origXml attribute
     */
    public byte[] getOrigXml() {
        return m_origXml;
    }

    /**
     * Mutator for origXml attribute
     * @param s new value for origXml attribute
     */
    public void setOrigXml(byte[] b)
    {
        m_origXml = b;
    }

    /**
     * Accessor for signatureMethod attribute
     * @return value of signatureMethod attribute
     */
    public String getSignatureMethod() {
        return m_signatureMethod;
    }

    /**
     * Mutator for signatureMethod attribute
     * @param str new value for signatureMethod attribute
     * @throws DigiDocException for validation errors
     */
    public void setSignatureMethod(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateSignatureMethod(str);
        if(ex != null)
            throw ex;
        m_signatureMethod = str;
    }

    /**
     * Helper method to validate a signature method
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateSignatureMethod(String str)
    {
        DigiDocException ex = null;
        if(str == null ||
                (!str.equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD) &&
                        !str.equals(SignedDoc.ECDSA_SHA1_SIGNATURE_METHOD)))
            ex = new DigiDocException(DigiDocException.ERR_SIGNATURE_METHOD,
                    "Currently supports only RSA-SHA1, RSA-SHA224, RSA-SHA256, RSA-SHA512, ECDSA-SHA1, ECDSA-SHA224, ECDSA-SHA256 and ECDSA-SHA512 signatures", null);
        return ex;
    }

    /**
     * Accessor for canonicalizationMethod attribute
     * @return value of canonicalizationMethod attribute
     */
    public String getCanonicalizationMethod() {
        return m_canonicalizationMethod;
    }

    /**
     * Mutator for canonicalizationMethod attribute
     * @param str new value for canonicalizationMethod attribute
     * @throws DigiDocException for validation errors
     */
    public void setCanonicalizationMethod(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateCanonicalizationMethod(str);
        if(ex != null)
            throw ex;
        m_canonicalizationMethod = str;
    }

    /**
     * Helper method to validate a signature method
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateCanonicalizationMethod(String str)
    {
        DigiDocException ex = null;
        if(str == null ||
                (!str.equals(SignedDoc.CANONICALIZATION_METHOD_20010315) &&
                        !str.equals(SignedDoc.CANONICALIZATION_METHOD_1_1) &&
                        !str.equals(SignedDoc.CANONICALIZATION_METHOD_2010_10_EXC)))
            ex= new DigiDocException(DigiDocException.ERR_CANONICALIZATION_METHOD,
                    "Currently supports only Canonical XML 1.0, 1.1 and exc", null);
        return ex;
    }

    /**
     * Returns the count of Reference objects
     * @return count of Reference objects
     */
    public int countReferences() {
        return ((m_references == null) ? 0 : m_references.size());
    }

    /**
     * Adds a new reference object
     * @param ref Reference object to add
     */
    public void addReference(Reference ref)
    {
        if(m_references == null)
            m_references = new ArrayList();
        m_references.add(ref);
    }

    /**
     * Returns the desired Reference object
     * @param idx index of the Reference object
     * @return desired Reference object
     */
    public Reference getReference(int idx) {
        return (Reference)m_references.get(idx);
    }


    /**
     * Returns the desired Reference object
     * @param df DataFile whose digest we are searching
     * @return desired Reference object
     */
    public Reference getReferenceForDataFile(DataFile df) {
        Reference ref = null;
        String fName = null;
        if(df.getFileName() != null) {
            File fT = new File(df.getFileName());
            fName = fT.getName(); // get not-absolute file-name
        }
        for(int i = 0; (m_references != null) && (i < m_references.size()); i++) {
            Reference r1 = (Reference)m_references.get(i);
            if(r1.getUri().equals("/" + df.getId())) {
                ref = r1;
                break;
            }
            if(r1.getUri().equals(df.getId()) || r1.getUri().equals(df.getFileName()) || r1.getUri().equals(fName)) {
                ref = r1;
                break;
            }
            if(r1.getUri().equals("#" + df.getId())) {
                ref = r1;
                break;
            }
        }
        return ref;
    }

    /**
     * Returns the desired Reference object
     * @param sp SignedProperties whose digest we are searching
     * @return desired Reference object
     */
    public Reference getReferenceForSignedProperties(SignedProperties sp) {
        Reference ref = null;
        for(int i = 0; (m_references != null) && (i < m_references.size()); i++) {
            Reference r1 = (Reference)m_references.get(i);
            if(r1.getUri().equals("#" + sp.getId())) {
                ref = r1;
                break;
            }
        }
        return ref;
    }

    /**
     * Returns the desired Reference object
     * @param dof DataObjectFormat whose digest we are searching
     * @return desired Reference object
     */
    public Reference getReferenceForDataObjectFormat(DataObjectFormat dof) {
        Reference ref = null;
        String sUri = dof.getObjectReference();
        if(sUri.startsWith("#")) sUri = sUri.substring(1);
        for(int i = 0; (m_references != null) && (i < m_references.size()); i++) {
            Reference r1 = (Reference)m_references.get(i);
            if(r1.getId().equals(sUri)) {
                ref = r1;
                break;
            }
        }
        return ref;
    }

    /**
     * Finds data-object-format for given reference
     * @param ref Reference object
     * @return DataObjectFormat
     */
    public DataObjectFormat getDataObjectFormatForReference(Reference ref)
    {
        if(getSignature().getSignedProperties() != null &&
                getSignature().getSignedProperties().getSignedDataObjectProperties() != null) {
            for(int i = 0; i < getSignature().getSignedProperties().getSignedDataObjectProperties().countDataObjectFormats(); i++) {
                DataObjectFormat dof = getSignature().getSignedProperties().getSignedDataObjectProperties().getDataObjectFormat(i);
                if(dof.getObjectReference().equals("#" + ref.getId()))
                    return dof;
            }
        }
        return null;
    }

    /**
     * Returns the last Reference object
     * @return desired Reference object
     */
    public Reference getLastReference() {
        return (Reference)m_references.get(m_references.size()-1);
    }

    /**
     * Helper method to validate references
     * @return exception or null for ok
     */
    private ArrayList validateReferences()
    {
        ArrayList errs = new ArrayList();
        if(countReferences() < 2) {
            errs.add(new DigiDocException(DigiDocException.ERR_NO_REFERENCES,
                    "At least 2 References are required!", null));
        } else {
            for(int i = 0; i < countReferences(); i++) {
                Reference ref = getReference(i);
                ArrayList e = ref.validate();
                if(!e.isEmpty())
                    errs.addAll(e);
            }
        }
        return errs;
    }

    /**
     * Helper method to validate the whole
     * SignedInfo object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateSignatureMethod(m_signatureMethod);
        if(ex != null)
            errs.add(ex);
        ex = validateCanonicalizationMethod(m_canonicalizationMethod);
        if(ex != null)
            errs.add(ex);
        ArrayList e = validateReferences();
        if(!e.isEmpty())
            errs.addAll(e);
        return errs;
    }

    /**
     * Calculates the digest of SignedInfo block
     * If the user has set origDigest attribute
     * which is allways done when reading the XML file,
     * then this digest is returned otherwise a new digest
     * is calculated.
     * @return SignedInfo block digest
     */
    public byte[] calculateDigest()
            throws DigiDocException
    {
        if(m_origDigest == null) {
            CanonicalizationFactory canFac = ConfigManager.
                    instance().getCanonicalizationFactory();
            DigiDocXmlGenFactory genFac = new DigiDocXmlGenFactory(m_signature.getSignedDoc());
            byte[] xml = genFac.signedInfoToXML(m_signature, this);
            byte[] tmp = canFac.canonicalize(xml, m_canonicalizationMethod);
            byte[] hash = null;
            if(m_signatureMethod.equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD) ||
                    m_signatureMethod.equals(SignedDoc.ECDSA_SHA1_SIGNATURE_METHOD))
                hash = SignedDoc.digestOfType(tmp, SignedDoc.SHA1_DIGEST_TYPE);
            return hash;
        }
        else
            return m_origDigest;
    }

}
