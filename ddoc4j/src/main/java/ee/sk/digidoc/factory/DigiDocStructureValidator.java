package ee.sk.digidoc.factory;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.XmlElemDef;
import ee.sk.digidoc.XmlElemInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Vector;

/**
 * Validates DigiDoc or bdoc structure.
 */
public class DigiDocStructureValidator {
    private static XmlElemDef eTransform = new XmlElemDef("Transform", true, null); /* 1.0 */
    private static XmlElemDef[] eTransformsCh = {eTransform}; /* 1.0 */
    private static XmlElemDef eTransforms = new XmlElemDef("Transforms", true, eTransformsCh); /* 1.0 */

    private static XmlElemDef eDigestMethod = new XmlElemDef("DigestMethod", false, null);
    private static XmlElemDef eDigestValue = new XmlElemDef("DigestValue", false, null);
    private static XmlElemDef[] eRefCh = {eDigestMethod, eDigestValue, eTransforms};
    private static XmlElemDef eReference = new XmlElemDef("Reference", true, eRefCh);
    private static XmlElemDef eSignatureMethod = new XmlElemDef("SignatureMethod", false, null);
    private static XmlElemDef eCanonicalizationMethod = new XmlElemDef("CanonicalizationMethod", false, null);
    private static XmlElemDef[] eSigInfoCh = {eCanonicalizationMethod, eSignatureMethod, eReference};
    private static XmlElemDef eSigInfo = new XmlElemDef("SignedInfo", false, eSigInfoCh);
    private static XmlElemDef eSigVal = new XmlElemDef("SignatureValue", false, null);
    private static XmlElemDef eModulus = new XmlElemDef("Modulus", false, null);
    private static XmlElemDef eExponent = new XmlElemDef("Exponent", false, null);
    private static XmlElemDef[] eRSAKeyValueCh = {eModulus, eExponent};
    private static XmlElemDef eRSAKeyValue = new XmlElemDef("RSAKeyValue", false, eRSAKeyValueCh);
    private static XmlElemDef[] eKeyValueCh = {eRSAKeyValue};
    private static XmlElemDef eKeyValue = new XmlElemDef("KeyValue", false, eKeyValueCh);
    private static XmlElemDef eX509Certificate = new XmlElemDef("X509Certificate", false, null);
    private static XmlElemDef[] eX509DataCh = {eX509Certificate};
    private static XmlElemDef eX509Data = new XmlElemDef("X509Data", false, eX509DataCh);
    private static XmlElemDef[] eKeyInfoCh = {eKeyValue,eX509Data};
    private static XmlElemDef eKeyInfo = new XmlElemDef("KeyInfo", false, eKeyInfoCh);


    private static XmlElemDef eEncapsulatedOCSPValue = new XmlElemDef("EncapsulatedOCSPValue", true, null);
    private static XmlElemDef[] eOCSPValuesCh = {eEncapsulatedOCSPValue};
    private static XmlElemDef eOCSPValues = new XmlElemDef("OCSPValues", false, eOCSPValuesCh);
    private static XmlElemDef[] eRevocationValuesCh = {eOCSPValues, eEncapsulatedOCSPValue /* 1.0 */};
    private static XmlElemDef eRevocationValues = new XmlElemDef("RevocationValues", false, eRevocationValuesCh);
    private static XmlElemDef eEncapsulatedX509Certificate = new XmlElemDef("EncapsulatedX509Certificate", true, null);
    private static XmlElemDef[] eCertificateValuesCh = {eEncapsulatedX509Certificate};
    private static XmlElemDef eCertificateValues = new XmlElemDef("CertificateValues", false, eCertificateValuesCh);
    private static XmlElemDef eResponderID = new XmlElemDef("ResponderID", false, null);
    private static XmlElemDef eProducedAt = new XmlElemDef("ProducedAt", false, null);
    private static XmlElemDef[] eOCSPIdentifierCh = {eResponderID,eProducedAt};
    private static XmlElemDef eOCSPIdentifier = new XmlElemDef("OCSPIdentifier", false, eOCSPIdentifierCh);
    private static XmlElemDef[] eDigestAlgAndValueCh = {eDigestMethod,eDigestValue};
    private static XmlElemDef eDigestAlgAndValue = new XmlElemDef("DigestAlgAndValue", false, eDigestAlgAndValueCh);
    private static XmlElemDef[] eOCSPRefCh = {eOCSPIdentifier,eDigestAlgAndValue};
    private static XmlElemDef eOCSPRef = new XmlElemDef("OCSPRef", true, eOCSPRefCh);
    private static XmlElemDef[] eOCSPRefsCh = {eOCSPRef};
    private static XmlElemDef eOCSPRefs = new XmlElemDef("OCSPRefs", false, eOCSPRefsCh);
    private static XmlElemDef[] eCompleteRevocationRefsCh = {eOCSPRefs};
    private static XmlElemDef eCompleteRevocationRefs = new XmlElemDef("CompleteRevocationRefs", false, eCompleteRevocationRefsCh);
    private static XmlElemDef eX509IssuerName = new XmlElemDef("X509IssuerName", false, null);
    private static XmlElemDef eX509SerialNumber = new XmlElemDef("X509SerialNumber", false, null);
    private static XmlElemDef[] eIssuerSerialCh = {eX509IssuerName,eX509SerialNumber};
    private static XmlElemDef eIssuerSerial = new XmlElemDef("IssuerSerial", false, eIssuerSerialCh);
    private static XmlElemDef[] eCertDigestCh = {eDigestMethod,eDigestValue};
    private static XmlElemDef eCertDigest = new XmlElemDef("CertDigest", false, eCertDigestCh);
    private static XmlElemDef[] eCertCh = {eCertDigest,eIssuerSerial};
    private static XmlElemDef eCert = new XmlElemDef("Cert", true, eCertCh);
    private static XmlElemDef[] eCertRefsCh = {eCert};
    private static XmlElemDef eCertRefs = new XmlElemDef("CertRefs", false, eCertRefsCh);
    private static XmlElemDef[] eCompleteCertificateRefsCh = {eCertRefs, eCert /* 1.0 */};
    private static XmlElemDef eCompleteCertificateRefs = new XmlElemDef("CompleteCertificateRefs", false, eCompleteCertificateRefsCh);
    private static XmlElemDef[] eUnsignedSignaturePropertiesCh = {eCompleteCertificateRefs,eCompleteRevocationRefs,eCertificateValues,eRevocationValues};
    private static XmlElemDef eUnsignedSignatureProperties = new XmlElemDef("UnsignedSignatureProperties", false, eUnsignedSignaturePropertiesCh);
    private static XmlElemDef[] eUnsignedPropertiesCh = {eUnsignedSignatureProperties};
    private static XmlElemDef eUnsignedProperties = new XmlElemDef("UnsignedProperties", false, eUnsignedPropertiesCh);

    private static XmlElemDef[] eSigningCertificateCh = {eCert};
    private static XmlElemDef eSigningCertificate = new XmlElemDef("SigningCertificate", false, eSigningCertificateCh);
    private static XmlElemDef eSigningTime = new XmlElemDef("SigningTime", false, null);
    private static XmlElemDef eSignaturePolicyImplied = new XmlElemDef("SignaturePolicyImplied", false, null);
    private static XmlElemDef eCity = new XmlElemDef("City", false, null);
    private static XmlElemDef eStateOrProvince = new XmlElemDef("StateOrProvince", false, null);
    private static XmlElemDef ePostalCode = new XmlElemDef("PostalCode", false, null);
    private static XmlElemDef eCountryName = new XmlElemDef("CountryName", false, null);
    private static XmlElemDef[] eSignatureProductionPlaceCh = {eCity,eStateOrProvince,ePostalCode,eCountryName};
    private static XmlElemDef eSignatureProductionPlace = new XmlElemDef("SignatureProductionPlace", false, eSignatureProductionPlaceCh);
    private static XmlElemDef eClaimedRole = new XmlElemDef("ClaimedRole", true, null);
    private static XmlElemDef[] eClaimedRolesCh = {eClaimedRole};
    private static XmlElemDef eClaimedRoles = new XmlElemDef("ClaimedRoles", false, eClaimedRolesCh);
    private static XmlElemDef[] eSignerRoleCh = {eClaimedRoles};
    private static XmlElemDef eSignerRole = new XmlElemDef("SignerRole", false, eSignerRoleCh);

    private static XmlElemDef eSPURI = new XmlElemDef("SPURI", false, null);
    private static XmlElemDef[] eSigPolicyQualifierCh = {eSPURI};
    private static XmlElemDef eSigPolicyQualifier = new XmlElemDef("SigPolicyQualifier", true, eSigPolicyQualifierCh);
    private static XmlElemDef[] eSigPolicyQualifiersCh = {eSigPolicyQualifier};
    private static XmlElemDef eSigPolicyQualifiers = new XmlElemDef("SigPolicyQualifiers", true, eSigPolicyQualifiersCh);
    private static XmlElemDef eIdentifier = new XmlElemDef("Identifier", false, null);
    private static XmlElemDef eDescription = new XmlElemDef("Description", false, null);
    private static XmlElemDef[] eSigPolicyIdCh = {eIdentifier,eDescription};
    private static XmlElemDef eSigPolicyId = new XmlElemDef("SigPolicyId", false, eSigPolicyIdCh);
    private static XmlElemDef[] eSigPolicyHashCh = {eDigestMethod,eDigestValue};
    private static XmlElemDef eSigPolicyHash = new XmlElemDef("SigPolicyHash", false, eSigPolicyHashCh);
    private static XmlElemDef[] eSignaturePolicyIdCh = {eSigPolicyId,eSigPolicyHash,eSigPolicyQualifiers};
    private static XmlElemDef eSignaturePolicyId = new XmlElemDef("SignaturePolicyId", false, eSignaturePolicyIdCh);
    private static XmlElemDef[] eSignaturePolicyIdentifierCh = {eSignaturePolicyId,eSignaturePolicyImplied};
    private static XmlElemDef eSignaturePolicyIdentifier = new XmlElemDef("SignaturePolicyIdentifier", false, eSignaturePolicyIdentifierCh);


    private static XmlElemDef eMimeType = new XmlElemDef("MimeType", false, null);
    private static XmlElemDef[] eDataObjectFormatCh = {eMimeType};
    private static XmlElemDef eDataObjectFormat = new XmlElemDef("DataObjectFormat", true, eDataObjectFormatCh);
    private static XmlElemDef[] eSignedDataObjectPropertiesCh = {eDataObjectFormat};
    private static XmlElemDef[] eSignedSignaturePropertiesCh = {eSigningTime,eSigningCertificate,eSignaturePolicyIdentifier,eSignatureProductionPlace,eSignerRole};
    private static XmlElemDef eSignedSignatureProperties = new XmlElemDef("SignedSignatureProperties", false, eSignedSignaturePropertiesCh);
    private static XmlElemDef eSignedDataObjectProperties = new XmlElemDef("SignedDataObjectProperties", false, eSignedDataObjectPropertiesCh);
    private static XmlElemDef[] eSignedPropertiesCh = {eSignedSignatureProperties,eSignedDataObjectProperties};
    private static XmlElemDef eSignedProperties  = new XmlElemDef("SignedProperties", false, eSignedPropertiesCh);

    private static XmlElemDef[] eQualifyingPropertiesCh = {eSignedProperties,eUnsignedProperties};
    private static XmlElemDef eQualifyingProperties = new XmlElemDef("QualifyingProperties", false, eQualifyingPropertiesCh);

    private static XmlElemDef[] eObjectCh = {eQualifyingProperties};
    private static XmlElemDef eObject = new XmlElemDef("Object", false, eObjectCh);
    private static XmlElemDef[] eSignatureCh = {eSigInfo,eSigVal,eKeyInfo,eObject};
    private static XmlElemDef eSignature = new XmlElemDef("Signature", true, eSignatureCh);
    private static XmlElemDef eDataFile = new XmlElemDef("DataFile", true, null);
    private static XmlElemDef[] eSigDocCh = {eDataFile, eSignature};
    private static XmlElemDef eSignedDoc = new XmlElemDef("SignedDoc", false, eSigDocCh );

    private static XmlElemDef[] eXAdESSignaturesCh = {eSignature};
    private static XmlElemDef eXAdESSignatures = new XmlElemDef("XAdESSignatures", false, eXAdESSignaturesCh );


    private static Logger m_logger = LoggerFactory.getLogger(DigiDocStructureValidator.class);

    public static DigiDocException validateElementPath(XmlElemInfo ePath)
    {
        DigiDocException ex = null;
        if(ePath == null) {
            ex = new DigiDocException(DigiDocException.ERR_PARSE_XML, "Null path!", null);
            return ex;
        }
        String sPath = ePath.getPath(true);
        String sRoot = ePath.getRootTag();
        XmlElemDef eCurr = null, eRoot = null;
        if(sRoot != null) {
            if(sRoot.equals("SignedDoc"))
                eRoot = eSignedDoc;
            if(sRoot.equals("XAdESSignatures"))
                eRoot = eXAdESSignatures;
            eCurr = eRoot.findChildByTag(ePath.getTag());
        }
        if(eCurr == null) {
            ex = new DigiDocException(DigiDocException.ERR_PARSE_XML, "Invalid xml element: " + sPath, null);
        }
        if(m_logger.isDebugEnabled())
            m_logger.debug("Validating path: " + sPath + " found: " + ((eCurr != null) ? "OK" : "NULL"));
        if(eRoot != null && eCurr != null) {
            Vector vecTags = ePath.getPathTags();
            if(!eRoot.hasPath(vecTags)) {
                ex = new DigiDocException(DigiDocException.ERR_PARSE_XML, "Invalid path: " + sPath + " for element: " + ePath.getTag(), null);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Invalid path: " + sPath + " for element: " + ePath.getTag());
            }
            if(ex == null) {
                Vector vecElem = new Vector();
                XmlElemInfo eParentInfo = ePath.getParent();
                if(eParentInfo != null) {
                    eParentInfo.findElementsWithTag(vecElem, ePath.getTag());
                    if(vecElem.size() > 1 && !eCurr.isMultiple()) {
                        ex = new DigiDocException(DigiDocException.ERR_PARSE_XML, "Multiple elements: " + ePath.getTag() + " not allowed under: " + eParentInfo.getTag(), null);
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Multiple elements: " + ePath.getTag() + " not allowed under: " + eParentInfo.getTag());
                    }
                }
            }
        }

        return ex;
    }



}
