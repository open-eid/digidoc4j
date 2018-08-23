package ee.sk.digidoc;

import java.io.Serializable;

/**
 * Models an XML-DSIG/ETSI SignaturePolicyIdentifier structure.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignaturePolicyIdentifier implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** SignaturePolicyId - id null then SignaturePolicyImplied */
    private SignaturePolicyId m_sigPolicyId;

    /**
     * Constructor for SignaturePolicyIdentifier
     * @param sigPolicyId SignaturePolicyId object.
     * If null then SignaturePolicyImplied
     */
    public SignaturePolicyIdentifier(SignaturePolicyId sigPolicyId)
    {
        m_sigPolicyId = sigPolicyId;
    }

    /**
     * Accessor for SignaturePolicyId element
     * @return value of SignaturePolicyId element
     */
    public SignaturePolicyId getSignaturePolicyId()
    {
        return m_sigPolicyId;
    }

    /**
     * Mutator for Description content
     * @param str new value for Description content
     */
    public void setSignaturePolicyId(SignaturePolicyId spi)
    {
        m_sigPolicyId = spi;
    }

}
