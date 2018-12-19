package org.digidoc4j.ddoc;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Models an XML-DSIG/ETSI SignaturePolicyId structure.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignaturePolicyId implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** SigPolicyId */
    private ObjectIdentifier m_sigPolicyId;
    /** SigPolicyHash - digest alg and hash */
    /** DigestMethod */
    private String m_digestAlg;
    /** DigestValue */
    private byte[] m_digestVal;
    /** SigPolicyQualifiers */
    private ArrayList m_qualifiers;


    public SignaturePolicyId(ObjectIdentifier oid)
    {
        m_sigPolicyId = oid;
        m_digestAlg = null;
        m_digestVal = null;
        m_qualifiers = null;
    }


    /**
     * Accessor for ObjectIdentifier content
     * @return value of ObjectIdentifier content
     */
    public ObjectIdentifier getSigPolicyId()
    {
        return m_sigPolicyId;
    }

    /**
     * Mutator for ObjectIdentifier content
     * @param oid new value for ObjectIdentifier content
     */
    public void setSigPolicyId(ObjectIdentifier oid)
    {
        m_sigPolicyId = oid;
    }

    /**
     * Accessor for DigestAlgorithm element
     * @return value of DigestAlgorithm element
     */
    public String getDigestAlgorithm()
    {
        return m_digestAlg;
    }

    /**
     * Mutator for DigestAlgorithm element
     * @param alg new value for DigestAlgorithm element
     */
    public void setDigestAlgorithm(String alg)
    {
        m_digestAlg = alg;
    }

    /**
     * Accessor for DigestValue element
     * @return value of DigestValue element
     */
    public byte[] getDigestValue()
    {
        return m_digestVal;
    }

    /**
     * Mutator for DigestValue element
     * @param hash new value for DigestValue element
     */
    public void setDigestValue(byte[] hash)
    {
        m_digestVal = hash;
    }


    /**
     * return the count of SigPolicyQualifier objects
     * @return count of SigPolicyQualifier objects
     */
    public int countSigPolicyQualifiers()
    {
        return ((m_qualifiers == null) ? 0 : m_qualifiers.size());
    }

    /**
     * Adds a new SigPolicyQualifier object
     * @param spq new object to be added
     */
    public void addSigPolicyQualifier(SigPolicyQualifier spq)
    {
        if(m_qualifiers == null)
            m_qualifiers = new ArrayList();
        m_qualifiers.add(spq);
    }

    /**
     * Retrieves SigPolicyQualifier element with the desired index
     * @param idx SigPolicyQualifier index
     * @return SigPolicyQualifier element or null if not found
     */
    public SigPolicyQualifier getSigPolicyQualifier(int idx)
    {
        if(m_qualifiers != null && idx < m_qualifiers.size()) {
            return (SigPolicyQualifier)m_qualifiers.get(idx);
        }
        return null; // not found
    }

}
