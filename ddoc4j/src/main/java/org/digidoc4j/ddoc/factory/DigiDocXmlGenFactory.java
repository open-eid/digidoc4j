package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.utils.ConvertUtils;
import org.digidoc4j.ddoc.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory class to handle all digidoc format xml generation issues
 * @author Veiko Sinivee
 */
public class DigiDocXmlGenFactory {
    private SignedDoc m_sdoc;

    private static final int NS_NONE = 0;
    private static final int NS_XMLDSIG = 1;
    private static final int NS_XADES = 2;
    private static final int NS_ASIC = 3;
    private Logger m_logger = LoggerFactory.getLogger(DigiDocXmlGenFactory.class);



    public DigiDocXmlGenFactory(SignedDoc sdoc)
    {
        m_sdoc = sdoc;
    }


    private void xmlElemTagStart(StringBuffer sb, int nNs, String tag, boolean bEnd, boolean bLf)
    {
        sb.append("<");
        if(nNs == NS_XMLDSIG && m_sdoc.getXmlDsigNs() != null && m_sdoc.getXmlDsigNs().length() > 0) {
            sb.append(m_sdoc.getXmlDsigNs());
            sb.append(":");
        }
        if(nNs == NS_XADES && m_sdoc.getXadesNs() != null && m_sdoc.getXadesNs().length() > 0) {
            sb.append(m_sdoc.getXadesNs());
            sb.append(":");
        }
        if(nNs == NS_ASIC && m_sdoc.getAsicNs() != null && m_sdoc.getAsicNs().length() > 0) {
            sb.append(m_sdoc.getAsicNs());
            sb.append(":");
        }
        sb.append(tag);
        if(bEnd)
            sb.append(">");
        if(bLf)
            sb.append("\n");
    }

    private void xmlElemTagEnd(StringBuffer sb, boolean bLf)
    {
        sb.append(">");
        if(bLf)
            sb.append("\n");
    }

    private void xmlElemEnd(StringBuffer sb, int nNs, String tag, boolean bLf)
    {
        sb.append("</");
        if(nNs == NS_XMLDSIG && m_sdoc.getXmlDsigNs() != null && m_sdoc.getXmlDsigNs().length() > 0) {
            sb.append(m_sdoc.getXmlDsigNs());
            sb.append(":");
        }
        if(nNs == NS_XADES && m_sdoc.getXadesNs() != null && m_sdoc.getXadesNs().length() > 0) {
            sb.append(m_sdoc.getXadesNs());
            sb.append(":");
        }
        if(nNs == NS_ASIC && m_sdoc.getAsicNs() != null && m_sdoc.getAsicNs().length() > 0) {
            sb.append(m_sdoc.getAsicNs());
            sb.append(":");
        }
        sb.append(tag);
        sb.append(">");
        if(bLf)
            sb.append("\n");
    }

    private void xmlElemAttr(StringBuffer sb, String name, String value)
    {
        sb.append(" ");
        sb.append(name);
        sb.append("=\"");
        sb.append(value);
        sb.append("\"");
    }

    private void xmlElemNsAttr(StringBuffer sb, int nNs)
    {
        sb.append(" ");
        sb.append("xmlns");
        if(nNs == NS_XMLDSIG && m_sdoc.getXmlDsigNs() != null && m_sdoc.getXmlDsigNs().length() > 0) {
            sb.append(":");
            sb.append(m_sdoc.getXmlDsigNs());
        }
        if(nNs == NS_XADES && m_sdoc.getXadesNs() != null && m_sdoc.getXadesNs().length() > 0) {
            sb.append(":");
            sb.append(m_sdoc.getXadesNs());
        }
        if(nNs == NS_ASIC && m_sdoc.getAsicNs() != null && m_sdoc.getAsicNs().length() > 0) {
            sb.append(":");
            sb.append(m_sdoc.getAsicNs());
        }
        sb.append("=\"");
        if(nNs == NS_XMLDSIG)
            sb.append(SignedDoc.xmlns_xmldsig);
        if(nNs == NS_XADES)
            sb.append(SignedDoc.xmlns_xades_123);
        if(nNs == NS_ASIC)
            sb.append(SignedDoc.xmlns_asic);
        sb.append("\"");
    }

    private void reference2xml(StringBuffer sb, Reference ref)
    {
        xmlElemTagStart(sb, NS_XMLDSIG, "Reference", false, false);
        // @Id
        if(ref.getId() != null && ref.getId().length() > 0)
            xmlElemAttr(sb, "Id", ref.getId());
        // @URI
        if(ref.getUri().indexOf("SignedProperties") != -1) {
            if(m_sdoc.getVersion().equals(SignedDoc.VERSION_1_2) ||
                    m_sdoc.getVersion().equals(SignedDoc.VERSION_1_3))
                xmlElemAttr(sb, "Type", "http://uri.etsi.org/01903/v1.1.1#SignedProperties");
            else
                xmlElemAttr(sb, "Type", SignedDoc.SIGNEDPROPERTIES_TYPE);
            String s = ref.getUri();
            if(s.startsWith("/") || s.startsWith("#"))
                s = s.charAt(0) + ConvertUtils.uriEncodePath(s.substring(1));
            else
                s = ConvertUtils.uriEncodePath(s);
            xmlElemAttr(sb, "URI", s);
        } else {
            String s = ref.getUri();
            if(s.startsWith("/") || s.startsWith("#"))
                s = s.charAt(0) + ConvertUtils.uriEncodePath(s.substring(1));
            else
                s = ConvertUtils.uriEncodePath(s);
            xmlElemAttr(sb, "URI", s);
        }
        xmlElemTagEnd(sb, true);
        // <Transforms></Transforms>
        if(ref.getTransformAlgorithm() != null && ref.getTransformAlgorithm().length() > 0) {
            xmlElemTagStart(sb, NS_XMLDSIG, "Transforms", true, false);
            xmlElemTagStart(sb, NS_XMLDSIG, "Transform", false, false);
            xmlElemAttr(sb, "Algorithm", ref.getTransformAlgorithm());
            xmlElemTagEnd(sb, true);
            xmlElemEnd(sb, NS_XMLDSIG, "Transform", true);
            xmlElemEnd(sb, NS_XMLDSIG, "Transforms", true);
        }
        // <DigestMethod>
        xmlElemTagStart(sb, NS_XMLDSIG, "DigestMethod", false, false);
        xmlElemAttr(sb, "Algorithm", ref.getDigestAlgorithm());
        xmlElemTagEnd(sb, true);
        xmlElemEnd(sb, NS_XMLDSIG, "DigestMethod", true);
        // <DigestValue>
        xmlElemTagStart(sb, NS_XMLDSIG, "DigestValue", true, false);
        sb.append(Base64Util.encode(ref.getDigestValue(), 0));
        xmlElemEnd(sb, NS_XMLDSIG, "DigestValue", true);
        xmlElemEnd(sb, NS_XMLDSIG, "Reference", true);
    }

    private void signedInfo2xml(StringBuffer sb, SignedInfo si, boolean bHashCalc)
    {
        xmlElemTagStart(sb, NS_XMLDSIG, "SignedInfo", false, false);
        // @xmlns
        if(si.getSignature() != null && si.getSignature().getSignedDoc() != null &&
                si.getSignature().getSignedDoc().getFormat() != null &&
                (si.getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
                        si.getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_SK_XML))) {
            xmlElemNsAttr(sb, NS_XMLDSIG);
        }
        if(bHashCalc && si.getSignature() != null && si.getSignature().getSignedDoc() != null &&
                si.getSignature().getSignedDoc().getFormat() != null &&
                si.getSignature().getSignedDoc().getVersion() != null &&
                si.getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) &&
                si.getSignature().getSignedDoc().getVersion().equals(SignedDoc.BDOC_VERSION_2_1)) {
            xmlElemNsAttr(sb, NS_ASIC);
            xmlElemNsAttr(sb, NS_XMLDSIG);
            xmlElemNsAttr(sb, NS_XADES);
        }
        // @Id
        if(si.getId() != null && si.getId().length() > 0)
            xmlElemAttr(sb, "Id", si.getId());
        xmlElemTagEnd(sb, true);
        // <CanonicalizationMethod>
        xmlElemTagStart(sb, NS_XMLDSIG, "CanonicalizationMethod", false, false);
        xmlElemAttr(sb, "Algorithm", si.getCanonicalizationMethod());
        xmlElemTagEnd(sb, true);
        xmlElemEnd(sb, NS_XMLDSIG, "CanonicalizationMethod", true);
        // <SignatureMethod>
        xmlElemTagStart(sb, NS_XMLDSIG, "SignatureMethod", false, false);
        xmlElemAttr(sb, "Algorithm", si.getSignatureMethod());
        xmlElemTagEnd(sb, true);
        xmlElemEnd(sb, NS_XMLDSIG, "SignatureMethod", true);
        for(int i = 0; i < si.countReferences(); i++) {
            Reference ref = (Reference)si.getReference(i);
            reference2xml(sb, ref);
        }
        xmlElemEnd(sb, NS_XMLDSIG, "SignedInfo", false);
    }

    public void signatureValue2xml(StringBuffer sb, SignatureValue sv, boolean bWithNs)
    {
        xmlElemTagStart(sb, NS_XMLDSIG, "SignatureValue", false, false);
        if(bWithNs)
            xmlElemNsAttr(sb, NS_XMLDSIG);
        // @Id
        if(sv.getId() != null && sv.getId().length() > 0)
            xmlElemAttr(sb, "Id", sv.getId());
        xmlElemTagEnd(sb, true);
        sb.append(Base64Util.encode(sv.getValue(), 0));
        xmlElemEnd(sb, NS_XMLDSIG, "SignatureValue", true);
    }

    private void certValue2xml(StringBuffer sb, CertValue cval)
            throws DigiDocException
    {
        if(cval.getType() == CertValue.CERTVAL_TYPE_SIGNER) {
            xmlElemTagStart(sb, NS_XMLDSIG, "X509Certificate", true, false);
        } else {
            xmlElemTagStart(sb, NS_XADES, "EncapsulatedX509Certificate", false, false);
            // @Id
            if(cval.getId() != null && cval.getId().length() > 0)
                xmlElemAttr(sb, "Id", cval.getId());
            xmlElemTagEnd(sb, true);
        }
        try {
            sb.append(Base64Util.encode(cval.getCert().getEncoded(), 64));
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_ENCODING);
        }
        if(cval.getType() == CertValue.CERTVAL_TYPE_SIGNER)
            xmlElemEnd(sb, NS_XMLDSIG, "X509Certificate", false);
        else
            xmlElemEnd(sb, NS_XADES, "EncapsulatedX509Certificate", true);
    }

    private void keyInfo2xml(StringBuffer sb, KeyInfo ki, Signature sig)
            throws DigiDocException
    {
        xmlElemTagStart(sb, NS_XMLDSIG, "KeyInfo", false, false);
        // @Id
        if(ki.getId() != null && ki.getId().length() > 0)
            xmlElemAttr(sb, "Id", ki.getId());
        xmlElemTagEnd(sb, true);
        if(!sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            // <KeyValue>
            xmlElemTagStart(sb, NS_XMLDSIG, "KeyValue", true, true);
            if(!sig.isEllipticCurveSiganture()) { // tegelikult ddoc-s meil EC allkirju ei olegi
                // <RSAKeyValue>
                xmlElemTagStart(sb, NS_XMLDSIG, "RSAKeyValue", true, true);
                // <Modulus>
                xmlElemTagStart(sb, NS_XMLDSIG, "Modulus", true, false);
                sb.append(Base64Util.encode(ki.getSignerKeyModulus().toByteArray(), 64));
                xmlElemEnd(sb, NS_XMLDSIG, "Modulus", true);
                // <Exponent>
                xmlElemTagStart(sb, NS_XMLDSIG, "Exponent", true, false);
                sb.append(Base64Util.encode(ki.getSignerKeyExponent().toByteArray(), 64));
                xmlElemEnd(sb, NS_XMLDSIG, "Exponent", true);
                // </RSAKeyValue>
                xmlElemEnd(sb, NS_XMLDSIG, "RSAKeyValue", true);
            }
            // </KeyValue>
            xmlElemEnd(sb, NS_XMLDSIG, "KeyValue", true);
        }
        // X509Data
        xmlElemTagStart(sb, NS_XMLDSIG, "X509Data", true, false);
        CertValue cval = sig.getCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
        if(cval != null)
            certValue2xml(sb, cval);
        xmlElemEnd(sb, NS_XMLDSIG, "X509Data", false);
        // </KeyInfo>
        xmlElemEnd(sb, NS_XMLDSIG, "KeyInfo", true);
    }

    private void certId2xml(StringBuffer sb, CertID ci, Signature sig)
    {
        xmlElemTagStart(sb, NS_XADES, "Cert", false, false);
        // in ddoc 1.1 and 1.2 we had forbidden Id atribute
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) &&
                (m_sdoc.getVersion().equals(SignedDoc.VERSION_1_1) ||
                        m_sdoc.getVersion().equals(SignedDoc.VERSION_1_2))) {
            // @Id
            if(ci.getId() != null && ci.getId().length() > 0)
                xmlElemAttr(sb, "Id", ci.getId());
        }
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            if(ci.getUri() != null && ci.getUri().length() > 0)
                xmlElemAttr(sb, "URI", ci.getUri());
        }
        xmlElemTagEnd(sb, true);
        // <CertDigest>
        xmlElemTagStart(sb, NS_XADES, "CertDigest", true, true);
        // <DigestMethod>
        xmlElemTagStart(sb, NS_XMLDSIG, "DigestMethod", false, false);
        xmlElemAttr(sb, "Algorithm", ci.getDigestAlgorithm());
        //if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
        //	xmlElemNsAttr(sb, NS_XMLDSIG);
        xmlElemTagEnd(sb, true);
        // </DigestMethod>
        xmlElemEnd(sb, NS_XMLDSIG, "DigestMethod", true);
        // <DigestValue>
        xmlElemTagStart(sb, NS_XMLDSIG, "DigestValue", false, false);
        //if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
        //	xmlElemNsAttr(sb, NS_XMLDSIG);
        xmlElemTagEnd(sb, false);
        sb.append(Base64Util.encode(ci.getDigestValue()));
        // </DigestValue>
        xmlElemEnd(sb, NS_XMLDSIG, "DigestValue", true);
        // </CertDigest>
        xmlElemEnd(sb, NS_XADES, "CertDigest", true);
        // <IssuerSerial>
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) &&
                (m_sdoc.getVersion().equals(SignedDoc.VERSION_1_1) ||
                        m_sdoc.getVersion().equals(SignedDoc.VERSION_1_2))) {
            xmlElemTagStart(sb, NS_XMLDSIG, "IssuerSerial", true, false);
            sb.append(ci.getSerial().toString());
            xmlElemEnd(sb, NS_XMLDSIG, "IssuerSerial", true);
        } else {
            xmlElemTagStart(sb, NS_XADES, "IssuerSerial", true, true);
            // <X509IssuerName>
            xmlElemTagStart(sb, NS_XMLDSIG, "X509IssuerName", false, false);
            if(!m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                xmlElemNsAttr(sb, NS_XMLDSIG);
            xmlElemTagEnd(sb, false);
            sb.append(ConvertUtils.escapeTextNode(ci.getIssuer()));
            // </X509IssuerName>
            xmlElemEnd(sb, NS_XMLDSIG, "X509IssuerName", true);
            // <X509SerialNumber>
            xmlElemTagStart(sb, NS_XMLDSIG, "X509SerialNumber", false, false);
            if(!m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                xmlElemNsAttr(sb, NS_XMLDSIG);
            xmlElemTagEnd(sb, false);
            sb.append(ci.getSerial().toString());
            // </X509SerialNumber>
            xmlElemEnd(sb, NS_XMLDSIG, "X509SerialNumber", true);
            // <IssuerSerial>
            xmlElemEnd(sb, NS_XADES, "IssuerSerial", true);
        }
        // </Cert>
        xmlElemEnd(sb,  NS_XADES, "Cert", true);
    }

    private void signatureProductionPlace2xml(StringBuffer sb, SignatureProductionPlace adr)
    {
        // <SignatureProductionPlace>
        xmlElemTagStart(sb, NS_XADES, "SignatureProductionPlace", true, true);
        if(adr.getCity() != null && adr.getCity().trim().length() > 0) { // <City>
            xmlElemTagStart(sb, NS_XADES, "City", true, false);
            sb.append(ConvertUtils.escapeTextNode(adr.getCity()));
            xmlElemEnd(sb,  NS_XADES, "City", true);
        }
        if(adr.getStateOrProvince() != null && adr.getStateOrProvince().trim().length() > 0) { // <StateOrProvince>
            xmlElemTagStart(sb, NS_XADES, "StateOrProvince", true, false);
            sb.append(ConvertUtils.escapeTextNode(adr.getStateOrProvince()));
            xmlElemEnd(sb,  NS_XADES, "StateOrProvince", true);
        }
        if(adr.getPostalCode() != null && adr.getPostalCode().trim().length() > 0) { // <PostalCode>
            xmlElemTagStart(sb, NS_XADES, "PostalCode", true, false);
            sb.append(ConvertUtils.escapeTextNode(adr.getPostalCode()));
            xmlElemEnd(sb,  NS_XADES, "PostalCode", true);
        }
        if(adr.getCountryName() != null && adr.getCountryName().trim().length() > 0) { // <CountryName>
            xmlElemTagStart(sb, NS_XADES, "CountryName", true, false);
            sb.append(ConvertUtils.escapeTextNode(adr.getCountryName()));
            xmlElemEnd(sb,  NS_XADES, "CountryName", true);
        }
        // </SignatureProductionPlace>
        xmlElemEnd(sb,  NS_XADES, "SignatureProductionPlace", true);
    }

    private void identifier2xml(StringBuffer sb, Identifier idf, Signature sig)
    {
        xmlElemTagStart(sb, NS_XADES, "Identifier", false, false);
        // @Qualifier
        if(idf.getQualifier() != null && idf.getQualifier().length() > 0)
            xmlElemAttr(sb, "Qualifier", idf.getQualifier());
        xmlElemTagEnd(sb, true);
        // oid or uri content
        if(idf.getUri() != null && idf.getUri().trim().length() > 0)
            sb.append(idf.getUri());
        // </Identifier>
        xmlElemEnd(sb,  NS_XADES, "Identifier", true);
    }

    private void objectIdentifier2xml(StringBuffer sb, ObjectIdentifier odf, String tag, Signature sig)
    {
        xmlElemTagStart(sb, NS_XADES, tag, true, true);
        // <Identifier>
        if(odf.getIdentifier() != null)
            identifier2xml(sb, odf.getIdentifier(), sig);
        // <Description>
        if(odf.getDescription() != null) {
            xmlElemTagStart(sb, NS_XADES, "Description", true, false);
            sb.append(odf.getDescription());
            xmlElemEnd(sb,  NS_XADES, "Description", true);
        }
        // <DocumentationReferences>
        if(odf.countDocumentationReferences() > 0) {
            xmlElemTagStart(sb, NS_XADES, "DocumentationReferences", true, true);
            for(int i = 0; i < odf.countDocumentationReferences(); i++) {
                xmlElemTagStart(sb, NS_XADES, "DocumentationReference", true, false);
                sb.append(odf.getDocumentationReference(i));
                xmlElemEnd(sb,  NS_XADES, "DocumentationReference", true);
            }
            xmlElemEnd(sb,  NS_XADES, "DocumentationReferences", true);
        }
        // </ObjectIdentifier>
        xmlElemEnd(sb,  NS_XADES, tag, true);
    }

    private void noticeRef2xml(StringBuffer sb, NoticeRef nrf, Signature sig)
    {
        xmlElemTagStart(sb, NS_XADES, "NoticeRef", true, true);
        // Organization
        xmlElemTagStart(sb, NS_XADES, "Organization", true, true);
        sb.append(nrf.getOrganization());
        xmlElemEnd(sb,  NS_XADES, "Organization", true);
        // NoticeNumbers
        if(nrf.countNoticeNumbers() > 0) {
            xmlElemTagStart(sb, NS_XADES, "NoticeNumbers", true, true);
            for(int i = 0; i < nrf.countNoticeNumbers(); i++) {
                xmlElemTagStart(sb, NS_XADES, "int", true, false);
                sb.append(new Integer(nrf.getNoticeNumber(i)).toString());
                xmlElemEnd(sb,  NS_XADES, "int", true);
            }
            xmlElemEnd(sb,  NS_XADES, "NoticeNumbers", true);
        }
        // </Identifier>
        xmlElemEnd(sb,  NS_XADES, "NoticeRef", true);
    }

    private void spUserNotice2xml(StringBuffer sb, SpUserNotice not, Signature sig)
    {
        if(not != null && (not.getExplicitText() != null || not.getNoticeRef() != null)) {
            xmlElemTagStart(sb, NS_XADES, "SPUserNotice", true, true);
            // NoticeRef
            if(not.getNoticeRef() != null)
                noticeRef2xml(sb, not.getNoticeRef(), sig);
            // ExplicitText
            if(not.getExplicitText() != null) {
                xmlElemTagStart(sb, NS_XADES, "ExplicitText", true, true);
                sb.append(not.getExplicitText());
                xmlElemEnd(sb,  NS_XADES, "ExplicitText", true);
            }
            xmlElemEnd(sb,  NS_XADES, "SPUserNotice", true);
        }
    }

    private void spUri2xml(StringBuffer sb, SpUri uri, Signature sig)
    {
        if(uri != null && uri.getUri() != null) {
            xmlElemTagStart(sb, NS_XADES, "SPURI", true, true);
            sb.append(uri.getUri());
            xmlElemEnd(sb,  NS_XADES, "SPURI", true);
        }
    }

    private void sigPolicyQualifier2xml(StringBuffer sb, SigPolicyQualifier spq, Signature sig)
    {
        if(spq != null && (spq instanceof SpUserNotice || spq instanceof SpUri)) {
            xmlElemTagStart(sb, NS_XADES, "SigPolicyQualifier", true, true);
            // SPUserNotice
            if(spq instanceof SpUserNotice)
                spUserNotice2xml(sb, (SpUserNotice)spq, sig);
            // SPURI
            if(spq instanceof SpUri)
                spUri2xml(sb, (SpUri)spq, sig);
            xmlElemEnd(sb,  NS_XADES, "SigPolicyQualifier", true);
        }
    }

    private void signaturePolicyId2xml(StringBuffer sb, SignaturePolicyId spi, Signature sig)
    {
        if(spi != null) {
            xmlElemTagStart(sb, NS_XADES, "SignaturePolicyId", true, true);
            // Identifier
            if(spi.getSigPolicyId() != null)
                objectIdentifier2xml(sb,spi.getSigPolicyId(), "SigPolicyId", sig);
            // SigPolicyHash
            if(spi.getDigestAlgorithm() != null || spi.getDigestValue() != null) {
                xmlElemTagStart(sb, NS_XADES, "SigPolicyHash", true, true);
                // <DigestMethod>
                xmlElemTagStart(sb, NS_XMLDSIG, "DigestMethod", false, false);
                xmlElemAttr(sb, "Algorithm", spi.getDigestAlgorithm());
                xmlElemTagEnd(sb, true);
                // </DigestMethod>
                xmlElemEnd(sb, NS_XMLDSIG, "DigestMethod", true);
                // <DigestValue>
                xmlElemTagStart(sb, NS_XMLDSIG, "DigestValue", false, false);
                xmlElemTagEnd(sb, false);
                sb.append(Base64Util.encode(spi.getDigestValue()));
                // </DigestValue>
                xmlElemEnd(sb, NS_XMLDSIG, "DigestValue", true);
                xmlElemEnd(sb,  NS_XADES, "SigPolicyHash", true);
            }
            // SigPolicyQualifiers
            if(spi.countSigPolicyQualifiers() > 0) {
                xmlElemTagStart(sb, NS_XADES, "SigPolicyQualifiers", true, true);
                for(int i = 0; i < spi.countSigPolicyQualifiers(); i++) {
                    sigPolicyQualifier2xml(sb, spi.getSigPolicyQualifier(i), sig);
                }
                xmlElemEnd(sb,  NS_XADES, "SigPolicyQualifiers", true);
            }
            xmlElemEnd(sb,  NS_XADES, "SignaturePolicyId", true);
        }
    }

    private void signaturePolicyIdentifier2xml(StringBuffer sb, SignaturePolicyIdentifier spi, Signature sig)
    {
        xmlElemTagStart(sb, NS_XADES, "SignaturePolicyIdentifier", true, true);
        if(spi != null && spi.getSignaturePolicyId() != null) {
            signaturePolicyId2xml(sb, spi.getSignaturePolicyId(), sig);
        } else {
            xmlElemTagStart(sb, NS_XADES, "SignaturePolicyImplied", true, true);
            xmlElemEnd(sb, NS_XADES, "SignaturePolicyImplied", true);
        }
        xmlElemEnd(sb, NS_XADES, "SignaturePolicyIdentifier", true);
    }

    private void dataObjectFormat2xml(StringBuffer sb, DataObjectFormat dof, Signature sig)
    {
        // <DataObjectFormat>
        xmlElemTagStart(sb, NS_XADES, "DataObjectFormat", false, false);
        // @ObjectReference
        if(dof.getObjectReference() != null && dof.getObjectReference().length() > 0)
            xmlElemAttr(sb, "ObjectReference", dof.getObjectReference());
        xmlElemTagEnd(sb, true);
        // <Description>
        if(dof.getDescription() != null && dof.getDescription().trim().length() > 0) {
            xmlElemTagStart(sb, NS_XADES, "Description", true, false);
            sb.append(dof.getDescription());
            xmlElemEnd(sb,  NS_XADES, "Description", true);
        }
        // <ObjectIdentifier>
        if(dof.getObjectIdentifier() != null) {
            objectIdentifier2xml(sb, dof.getObjectIdentifier(), "ObjectIdentifier", sig);
        }
        // <MimeType>
        if(dof.getMimeType() != null && dof.getMimeType().trim().length() > 0) {
            xmlElemTagStart(sb, NS_XADES, "MimeType", true, false);
            sb.append(dof.getMimeType());
            xmlElemEnd(sb,  NS_XADES, "MimeType", true);
        }
        // <Encoding>
        if(dof.getEncoding() != null && dof.getEncoding().trim().length() > 0) {
            xmlElemTagStart(sb, NS_XADES, "Encoding", true, false);
            sb.append(dof.getEncoding());
            xmlElemEnd(sb,  NS_XADES, "Encoding", true);
        }
        // </DataObjectFormat>
        xmlElemEnd(sb,  NS_XADES, "DataObjectFormat", true);
    }

    private void signedDataObjectProperties2xml(StringBuffer sb, SignedDataObjectProperties sdof, Signature sig)
    {
        // <SignedDataObjectProperties>
        xmlElemTagStart(sb, NS_XADES, "SignedDataObjectProperties", true, true);
        // <DataObjectFormat>
        for(int i = 0; (sdof != null) && (i < sdof.countDataObjectFormats()); i++) {
            DataObjectFormat dof = sdof.getDataObjectFormat(i);
            if(dof != null)
                dataObjectFormat2xml(sb, dof, sig);
        }
        // TODO: other structure elements not used

        // </SignedDataObjectProperties>
        xmlElemEnd(sb,  NS_XADES, "SignedDataObjectProperties", true);
    }

    private void signedProperties2xml(StringBuffer sb, SignedProperties sp, Signature sig, boolean bWithNs)
            throws DigiDocException
    {
        xmlElemTagStart(sb, NS_XADES, "SignedProperties", false, false);
        // in ddoc 1.1 and 1.2 we had wrong namespace and forbidden Target atribute
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) &&
                (m_sdoc.getVersion().equals(SignedDoc.VERSION_1_1) ||
                        m_sdoc.getVersion().equals(SignedDoc.VERSION_1_2))) {
            xmlElemAttr(sb, "Target", "#" + sig.getId());
            xmlElemAttr(sb, "xmlns", SignedDoc.xmlns_xmldsig);
        } else {
            if(bWithNs && sig != null && sig.getSignedDoc() != null &&
                    sig.getSignedDoc().getFormat() != null &&
                    sig.getSignedDoc().getVersion() != null &&
                    sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) &&
                    sig.getSignedDoc().getVersion().equals(SignedDoc.BDOC_VERSION_2_1)) {
                xmlElemNsAttr(sb, NS_ASIC);
                xmlElemNsAttr(sb, NS_XMLDSIG);
                xmlElemNsAttr(sb, NS_XADES);
            }
        }
        // @Id
        if(sp.getId() != null && sp.getId().length() > 0)
            xmlElemAttr(sb, "Id", sp.getId());
        xmlElemTagEnd(sb, true);
        // <SignedSignatureProperties>
        xmlElemTagStart(sb, NS_XADES, "SignedSignatureProperties", false, false);
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            xmlElemAttr(sb, "Id", sig.getId() + "-SignedSignatureProperties");
        xmlElemTagEnd(sb, true);
        // <SigningTime>
        xmlElemTagStart(sb, NS_XADES, "SigningTime", true, false);
        sb.append(ConvertUtils.date2string(sp.getSigningTime(), m_sdoc));
        // </SigningTime>
        xmlElemEnd(sb,  NS_XADES, "SigningTime", true);
        // <SigningCertificate>
        xmlElemTagStart(sb, NS_XADES, "SigningCertificate", true, true);
        CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_SIGNER);
        if(cid != null)
            certId2xml(sb, cid, sig);
        // </SigningCertificate>
        xmlElemEnd(sb,  NS_XADES, "SigningCertificate", true);
        // signature policy
        if(sig.getSignedProperties() != null && sig.getSignedProperties().getSignaturePolicyIdentifier() != null)
            signaturePolicyIdentifier2xml(sb, sig.getSignedProperties().getSignaturePolicyIdentifier(), sig);
        // <SignatureProductionPlace>
        if(sp.getSignatureProductionPlace() != null) {
            sb.append("\n");
            signatureProductionPlace2xml(sb, sp.getSignatureProductionPlace());
        }
        // <ClaimedRoles>
        if(sp.countClaimedRoles() > 0) {
            sb.append("\n");
            // <SignerRole>
            xmlElemTagStart(sb, NS_XADES, "SignerRole", true, true);
            // <ClaimedRoles>
            xmlElemTagStart(sb, NS_XADES, "ClaimedRoles", true, true);
            for(int i = 0; i < sp.countClaimedRoles(); i++) {
                xmlElemTagStart(sb, NS_XADES, "ClaimedRole", true, false);
                sb.append(ConvertUtils.escapeTextNode(sp.getClaimedRole(i)));
                xmlElemEnd(sb,  NS_XADES, "ClaimedRole", true);
            }
            // </ClaimedRoles>
            xmlElemEnd(sb,  NS_XADES, "ClaimedRoles", true);
            // </SignerRole>
            xmlElemEnd(sb,  NS_XADES, "SignerRole", true);
        }
        // </SignedSignatureProperties>
        xmlElemEnd(sb,  NS_XADES, "SignedSignatureProperties", true);
        // <SignedDataObjectProperties>
        signedDataObjectProperties2xml(sb, sp.getSignedDataObjectProperties(), sig);
        // </SignedProperties>
        xmlElemEnd(sb, NS_XADES, "SignedProperties", false);
    }

    public void timestampInfo2xml(StringBuffer sb, TimestampInfo ti, boolean bWithNs)
    {
        switch(ti.getType()) {
            case TimestampInfo.TIMESTAMP_TYPE_ALL_DATA_OBJECTS:
                xmlElemTagStart(sb, NS_XADES, "AllDataObjectsTimeStamp", false, false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_INDIVIDUAL_DATA_OBJECTS:
                xmlElemTagStart(sb, NS_XADES, "IndividualDataObjectsTimeStamp", false, false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_SIGNATURE:
                xmlElemTagStart(sb, NS_XADES, "SignatureTimeStamp", false, false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS:
                xmlElemTagStart(sb, NS_XADES, "SigAndRefsTimeStamp", false, false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_REFS_ONLY:
                xmlElemTagStart(sb, NS_XADES, "RefsOnlyTimeStamp", false, false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_ARCHIVE:
                xmlElemTagStart(sb, NS_XADES, "ArchiveTimeStamp", false, false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_XADES:
                xmlElemTagStart(sb, NS_XADES, "XAdESTimeStamp", false, false);
                break;
        }
        if(bWithNs) {
            xmlElemNsAttr(sb, NS_XMLDSIG);
            xmlElemNsAttr(sb, NS_XADES);
        }
        // @Id
        if(ti.getId() != null && ti.getId().length() > 0)
            xmlElemAttr(sb, "Id", ti.getId());
        xmlElemTagEnd(sb, true);
        for(int i = 0; i < ti.countIncludeInfos(); i++) {
            IncludeInfo inc = ti.getIncludeInfo(i);
            if(inc != null) {
                xmlElemTagStart(sb, NS_XADES, "Include", false, false);
                xmlElemAttr(sb, "URI", inc.getUri());
                xmlElemTagEnd(sb, true);
                xmlElemEnd(sb,  NS_XADES, "Include", false);
            }
        }
        // EncapsulatedTimeStamp
        xmlElemTagStart(sb, NS_XADES, "EncapsulatedTimeStamp", true, false);
        try {
            sb.append(Base64Util.encode(ti.getTimeStampToken().getEncoded()));
        } catch(Exception ex) {
            m_logger.error("Error encoding stimestamp: " + ex);
        }
        xmlElemEnd(sb,  NS_XADES, "EncapsulatedTimeStamp", false);
        switch(ti.getType()) {
            case TimestampInfo.TIMESTAMP_TYPE_ALL_DATA_OBJECTS:
                xmlElemEnd(sb,  NS_XADES, "AllDataObjectsTimeStamp", false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_INDIVIDUAL_DATA_OBJECTS:
                xmlElemEnd(sb,  NS_XADES, "IndividualDataObjectsTimeStamp", false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_SIGNATURE:
                xmlElemEnd(sb,  NS_XADES, "SignatureTimeStamp", false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS:
                xmlElemEnd(sb,  NS_XADES, "SigAndRefsTimeStamp", false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_REFS_ONLY:
                xmlElemEnd(sb,  NS_XADES, "RefsOnlyTimeStamp", false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_ARCHIVE:
                xmlElemEnd(sb,  NS_XADES, "ArchiveTimeStamp", false);
                break;
            case TimestampInfo.TIMESTAMP_TYPE_XADES:
                xmlElemEnd(sb,  NS_XADES, "XAdESTimeStamp", false);
                break;
        }
    }

    public void completeCertificateRefs2xml(StringBuffer sb, CompleteCertificateRefs crefs, Signature sig, boolean bWithNs)
    {
        // <CompleteCertificateRefs>
        xmlElemTagStart(sb, NS_XADES, "CompleteCertificateRefs", false, false);
        if(bWithNs) {
            xmlElemNsAttr(sb, NS_XMLDSIG);
            xmlElemNsAttr(sb, NS_XADES);
        }
        if(m_sdoc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            xmlElemAttr(sb, "Id", sig.getId() + "-CERTREFS");
        xmlElemTagEnd(sb, false);
        if(m_sdoc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            // <CertRefs>
            xmlElemTagStart(sb, NS_XADES, "CertRefs", true, true);
        for(int i = 0; i < crefs.countCertIDs(); i++) {
            CertID cid = crefs.getCertID(i);
            if(/*(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) && cid.getType() == CertID.CERTID_TYPE_RESPONDER_CA) ||
    		   (!m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) &&*/ cid.getType() != CertID.CERTID_TYPE_SIGNER) {
                certId2xml(sb, cid, sig);
            }
        }
        if(m_sdoc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            // </CertRefs>
            xmlElemEnd(sb,  NS_XADES, "CertRefs", false);
        // </CompleteCertificateRefs>
        xmlElemEnd(sb,  NS_XADES, "CompleteCertificateRefs", false);
    }

    private void ocspRef2xml(StringBuffer sb, OcspRef orf)
            throws DigiDocException
    {
        // <OCSPRef>
        xmlElemTagStart(sb, NS_XADES, "OCSPRef", true, true);
        // <OCSPIdentifier>
        xmlElemTagStart(sb, NS_XADES, "OCSPIdentifier", false, false);
        xmlElemAttr(sb, "URI", orf.getUri());
        xmlElemTagEnd(sb, true);
        // <ResponderID>
        xmlElemTagStart(sb, NS_XADES, "ResponderID", true, false);
        // <ByName>
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            xmlElemTagStart(sb, NS_XADES, "ByName", true, false);
        String s = orf.getResponderId();
        if(s.startsWith("byName: ")) s = s.substring("byName: ".length());
        if(s.startsWith("byKey: ")) s = s.substring("byKey: ".length());
        sb.append(ConvertUtils.escapeTextNode(s));
        // </ByName>
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            xmlElemEnd(sb,  NS_XADES, "ByName", false);
        // </ResponderID>
        xmlElemEnd(sb,  NS_XADES, "ResponderID", false);
        // <ProducedAt>
        xmlElemTagStart(sb, NS_XADES, "ProducedAt", true, false);
        sb.append(ConvertUtils.date2string(orf.getProducedAt(), m_sdoc));
        xmlElemEnd(sb,  NS_XADES, "ProducedAt", true);
        // </OCSPIdentifier>
        xmlElemEnd(sb,  NS_XADES, "OCSPIdentifier", true);
        // <DigestAlgAndValue>
        xmlElemTagStart(sb, NS_XADES, "DigestAlgAndValue", true, true);
        // <DigestMethod>
        xmlElemTagStart(sb, NS_XMLDSIG, "DigestMethod", false, false);
        xmlElemAttr(sb, "Algorithm", orf.getDigestAlgorithm());
        //if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
        //	xmlElemNsAttr(sb, NS_XADES);
        xmlElemTagEnd(sb, true);
        xmlElemEnd(sb, NS_XMLDSIG, "DigestMethod", false);
        // <DigestValue>
        xmlElemTagStart(sb, NS_XMLDSIG, "DigestValue", false, false);
        //if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
        //   xmlElemNsAttr(sb, NS_XADES);
        xmlElemTagEnd(sb, false);
        sb.append(Base64Util.encode(orf.getDigestValue(), 0));
        xmlElemEnd(sb, NS_XMLDSIG, "DigestValue", true);
        // </DigestAlgAndValue>
        xmlElemEnd(sb, NS_XADES, "DigestAlgAndValue", true);
        // </OCSPRef>
        xmlElemEnd(sb, NS_XADES, "OCSPRef", true);
    }

    public void completeRevocationRefs2xml(StringBuffer sb, CompleteRevocationRefs rrefs, Signature sig, boolean bWithNs)
            throws DigiDocException
    {
        // <CompleteRevocationRefs>
        xmlElemTagStart(sb, NS_XADES, "CompleteRevocationRefs", false, false);
        if(bWithNs) {
            xmlElemNsAttr(sb, NS_XMLDSIG);
            xmlElemNsAttr(sb, NS_XADES);
        }
        // @Id
        xmlElemAttr(sb, "Id", sig.getId() + "-REVOCREFS");
        xmlElemTagEnd(sb, true);
        // <OCSPRefs>
        xmlElemTagStart(sb, NS_XADES, "OCSPRefs", true, true);

        for(int i = 0; i < rrefs.countOcspRefs(); i++) {
            OcspRef orf = rrefs.getOcspRefById(i);
            ocspRef2xml(sb, orf);
        }

        // </OCSPRefs>
        xmlElemEnd(sb, NS_XADES, "OCSPRefs", true);
        // </CompleteRevocationRefs>
        xmlElemEnd(sb, NS_XADES, "CompleteRevocationRefs", false);
    }

    private void unsignedProperties2xml(StringBuffer sb, UnsignedProperties sp, Signature sig) // , boolean bWithNs
            throws DigiDocException
    {
        // <UnsignedProperties>
        xmlElemTagStart(sb, NS_XADES, "UnsignedProperties", false, false);
        // in ddoc 1.1 and 1.2 we had forbidden Target atribute
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) &&
                (m_sdoc.getVersion().equals(SignedDoc.VERSION_1_1) ||
                        m_sdoc.getVersion().equals(SignedDoc.VERSION_1_2))) {
            xmlElemAttr(sb, "Target", "#" + sig.getId());
        } else {
            if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                xmlElemAttr(sb, "Id", sig.getId() + "-UnsigedProperties");
            if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                //xmlElemNsAttr(sb, NS_XADES);
                ;
            else
                xmlElemAttr(sb, "xmlns", SignedDoc.xmlns_etsi);
        }
        xmlElemTagEnd(sb, true);
        // <UnsignedSignatureProperties>
        xmlElemTagStart(sb, NS_XADES, "UnsignedSignatureProperties", false, false);
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            xmlElemAttr(sb, "Id", sig.getId() + "-UnsigedSignatureProperties");
        xmlElemTagEnd(sb, true);
        // profiles T/CL/TS/TSA
        if(sig.getProfile().equals(SignedDoc.BDOC_PROFILE_T) ||
                sig.getProfile().equals(SignedDoc.BDOC_PROFILE_CL) ||
                sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TS) ||
                sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TSA)) {
            // <SignatureTimeStamp>
            TimestampInfo ti = sig.getTimestampInfoOfType(TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
            if(ti != null)
                timestampInfo2xml(sb, ti, false);
        }
        // <CompleteCertificateRefs> and <CompleteRevocationRefs> not used in bdoc 2.0
        if(!m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ||
                !m_sdoc.getVersion().equals(SignedDoc.BDOC_VERSION_2_1)) {
            //	timestampInfo2xml(sb, ti, false);
            // profiles T/CL/TS/TSA/TM/TMA
            if(sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TM) ||
                    sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TMA) ||
                    sig.getProfile().equals(SignedDoc.BDOC_PROFILE_CL) ||
                    sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TS) ||
                    sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TSA)) {
                // <CompleteCertificateRefs>
                completeCertificateRefs2xml(sb, sp.getCompleteCertificateRefs(), sig, false);
                // <CompleteRevocationRefs>
                completeRevocationRefs2xml(sb, sp.getCompleteRevocationRefs(), sig, false);
            }
        }
        // profiles TS/TSA
        if(sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TS) ||
                sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TSA)) {
            // <SigAndRefsTimeStamp>
            TimestampInfo ti = sig.getTimestampInfoOfType(TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS);
            if(ti != null)
                timestampInfo2xml(sb, ti, false);
        }
        // profiles TS/TSA/TM/TMA
        if(sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TM) ||
                sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TMA) ||
                sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TS) ||
                sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TSA)) {
            // <CertificateValues>
            int nCerts = 0;
            for(int i = 0; i < sig.countCertValues(); i++) {
                CertValue cval = sig.getCertValue(i);
                if(cval != null && cval.getType() != CertValue.CERTVAL_TYPE_SIGNER)
                    nCerts++;
            }
            if(nCerts > 0) {
                // <CertificateValues>
                xmlElemTagStart(sb, NS_XADES, "CertificateValues", false, false);
                if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                    xmlElemAttr(sb, "Id", sig.getId() + "-CertificateValues");
                xmlElemTagEnd(sb, true);
                for(int i = 0; i < sig.countCertValues(); i++) {
                    CertValue cval = sig.getCertValue(i);
                    if(cval != null && cval.getType() != CertValue.CERTVAL_TYPE_SIGNER)
                        certValue2xml(sb, cval);
                }
                xmlElemEnd(sb, NS_XADES, "CertificateValues", true);
            }
            // <RevocationValues>
            xmlElemTagStart(sb, NS_XADES, "RevocationValues", false, false);
            if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                xmlElemAttr(sb, "Id", sig.getId() + "-RevocationValues");
            xmlElemTagEnd(sb, true);
            // <OCSPValues>
            xmlElemTagStart(sb, NS_XADES, "OCSPValues", true, false);
            for(int i = 0; i < sp.countNotaries(); i++) {
                Notary not = sp.getNotaryById(i);
                // <EncapsulatedOCSPValue>
                xmlElemTagStart(sb, NS_XADES, "EncapsulatedOCSPValue", false, false);
                if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ||
                        (m_sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) &&
                                m_sdoc.getVersion().equals(SignedDoc.VERSION_1_3)))
                    xmlElemAttr(sb, "Id", not.getId());
                xmlElemTagEnd(sb, true);
                sb.append(Base64Util.encode(not.getOcspResponseData(), 64));
                // </EncapsulatedOCSPValue>
                xmlElemEnd(sb, NS_XADES, "EncapsulatedOCSPValue", true);
            }
            // </OCSPValues>
            xmlElemEnd(sb, NS_XADES, "OCSPValues", false);
            // </RevocationValues>
            xmlElemEnd(sb, NS_XADES, "RevocationValues", false);
        } // profiles TM/TMA/TS/TSA
        // </UnsignedSignatureProperties>
        xmlElemEnd(sb, NS_XADES, "UnsignedSignatureProperties", true);
        // </UnsignedProperties>
        xmlElemEnd(sb, NS_XADES, "UnsignedProperties", false);
    }

    /**
     * Formats signature in XML
     * @param sig Signature object
     * @return xml form of Signature
     */
    public String signature2xml(Signature sig)
            throws DigiDocException
    {
        StringBuffer sb = new StringBuffer();
        if(sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC))
            sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        // <XAdESSignatures
        if(sig.getSignedDoc().getVersion().equals(SignedDoc.BDOC_VERSION_2_1))
            sb.append("<asic:XAdESSignatures xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\" " +
                    "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">\n");
        // <Signature>
        // @Id<Object><QualifyingProperties xmlns="http://uri.etsi.org/01903/v1.1.1
        xmlElemTagStart(sb, NS_XMLDSIG, "Signature", false, false);
        if(sig.getId() != null && sig.getId().length() > 0)
            xmlElemAttr(sb, "Id", sig.getId());
        if(!m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ||
                !m_sdoc.getVersion().equals(SignedDoc.BDOC_VERSION_2_1)) {
            // @xmlns
            xmlElemNsAttr(sb, NS_XMLDSIG);
        }
        xmlElemTagEnd(sb, true);
        // <SignedInfo>
        signedInfo2xml(sb, sig.getSignedInfo(), false);
        // <SignatureValue>
        if(sig.getSignatureValue() != null)
            signatureValue2xml(sb, sig.getSignatureValue(), false);
        // <KeyInfo>
        keyInfo2xml(sb, sig.getKeyInfo(), sig);
        // <Object>
        if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            xmlElemTagStart(sb, NS_XMLDSIG, "Object", false, false);
            xmlElemAttr(sb, "Id", sig.getId() + "-object-xades");
            xmlElemTagEnd(sb, false);
        } else
            xmlElemTagStart(sb, NS_XMLDSIG, "Object", true, false);
        // <QualifyingProperties>
        xmlElemTagStart(sb, NS_XADES, "QualifyingProperties", false, false);
        if(m_sdoc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            // @Id
            if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                xmlElemAttr(sb, "Id", sig.getId() + "-QualifyingProperties");
            // @Target
            xmlElemAttr(sb, "Target", "#" + sig.getId());
            // @xmlns
            if(m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                xmlElemNsAttr(sb, NS_XADES);
            else
                xmlElemAttr(sb, "xmlns", SignedDoc.xmlns_etsi);
        }
        xmlElemTagEnd(sb, false);
        // <SignedProperties>
        signedProperties2xml(sb, sig.getSignedProperties(), sig, false);
        // Profiles T / C / TM / TS
        if(sig.getUnsignedProperties() != null) {
            // <UnsignedProperties>
            unsignedProperties2xml(sb, sig.getUnsignedProperties(), sig);
        } // Profiles: T/C/TM/TS
        // </QualifyingProperties>
        xmlElemEnd(sb, NS_XADES, "QualifyingProperties", false);
        // </Object>
        xmlElemEnd(sb, NS_XMLDSIG, "Object", true);
        // </Signature>
        xmlElemEnd(sb, NS_XMLDSIG, "Signature", true);
        // </XAdESSignatures
        if(sig.getSignedDoc().getVersion().equals(SignedDoc.BDOC_VERSION_2_1))
            sb.append("</asic:XAdESSignatures>");
        return sb.toString();
    }

    /**
     * Formats Signature object to XML
     * @param sig Signature object
     * @return XML form of signature
     * @throws DigiDocException
     */
    public byte[] signatureToXML(Signature sig)
            throws DigiDocException
    {
        if(sig.getOrigContent() != null) {
            return sig.getOrigContent();
        } else {
            String sXml = signature2xml(sig);
            try {
                return ConvertUtils.str2data(sXml);
            } catch(Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
            }
            return null;
        }
    }

    /**
     * Formats Signature object to XML
     * @param sig Signature object
     * @return XML form of signature
     * @throws DigiDocException
     */
    public byte[] signedPropertiesToXML(Signature sig, SignedProperties sp)
            throws DigiDocException
    {
        StringBuffer sb = new StringBuffer();
        signedProperties2xml(sb, sp, sig, true);
        String sXml = sb.toString();
        try {
            return ConvertUtils.str2data(sXml);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return null;
    }

    /**
     * Formats Signatore object to XML
     * @param sig Signature object
     * @return XML form of signature
     * @throws DigiDocException
     */
    public byte[] unsignedPropertiesToXML(Signature sig, UnsignedProperties usp)
            throws DigiDocException
    {
        StringBuffer sb = new StringBuffer();
        unsignedProperties2xml(sb, usp, sig);
        String sXml = sb.toString();
        try {
            return ConvertUtils.str2data(sXml);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return null;
    }

    /**
     * Formats Signatore object to XML
     * @param sig Signature object
     * @return XML form of signature
     * @throws DigiDocException
     */
    public byte[] signedInfoToXML(Signature sig, SignedInfo si)
            throws DigiDocException
    {
        StringBuffer sb = new StringBuffer();
        signedInfo2xml(sb, si, true);
        String sXml = sb.toString();
        try {
            return ConvertUtils.str2data(sXml);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return null;
    }

}
