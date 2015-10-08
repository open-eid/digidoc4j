/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import eu.europa.ec.markt.dss.ASiCNamespaces;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.signature.validation.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.RespID;
import org.digidoc4j.Signature;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import java.net.URI;
import java.util.*;

import static eu.europa.ec.markt.dss.DSSXMLUtils.createDocument;

import org.digidoc4j.SignatureProfile;
import static org.digidoc4j.SignatureProfile.*;


/**
 * BDoc signature implementation.
 */
public class BDocSignature implements Signature {
  private static final Logger logger = LoggerFactory.getLogger(BDocSignature.class);
  private XAdESSignature origin;
  private SignatureProductionPlace signerLocation;
  private List<DigiDoc4JException> validationErrors = new ArrayList<>();
  private static final Map<SignatureLevel, SignatureProfile> signatureProfileMap =
      new HashMap<SignatureLevel, SignatureProfile>() {
        {
          put(SignatureLevel.XAdES_BASELINE_B, B_BES);
          put(SignatureLevel.XAdES_BASELINE_T, LT);
          put(SignatureLevel.XAdES_BASELINE_LT, LT);
          put(SignatureLevel.XAdES_BASELINE_LTA, LTA);
          put(SignatureLevel.XAdES_A, LTA);
        }
      };

  /**
   * Create a new BDoc signature.
   *
   * @param signature XAdES signature to use for the BDoc signature
   */
  public BDocSignature(XAdESSignature signature) {
    logger.debug("");
    origin = signature;
    signerLocation = signature.getSignatureProductionPlace();
    logger.debug("New BDoc signature created");
  }

  /**
   * * Create a new BDOC signature.
   *
   * @param signature        XAdES signature to use for the BDoc signature
   * @param validationErrors list of DigiDoc4J exceptions to add to the signature
   */
  public BDocSignature(XAdESSignature signature, List<DigiDoc4JException> validationErrors) {
    logger.debug("");
    origin = signature;
    signerLocation = signature.getSignatureProductionPlace();
    this.validationErrors = validationErrors;
    logger.debug("New BDoc signature created");
  }

  @Override
  public String getCity() {
    logger.debug("");
    return signerLocation == null ? null : signerLocation.getCity();
  }

  @Override
  public String getCountryName() {
    logger.debug("");
    return signerLocation == null ? null : signerLocation.getCountryName();
  }

  @Override
  public String getId() {
    logger.debug("");
    return origin.getId();
  }

  @Override
  public byte[] getOCSPNonce() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public X509Cert getOCSPCertificate() {
    logger.debug("");

    if (origin.getOCSPSource().getContainedOCSPResponses().size() == 0)
      return null;

    String ocspCN = getOCSPCommonName();
    for (CertificateToken cert : origin.getCertPool().getCertificateTokens()) {
      String value = getCN(new X500Name(cert.getSubjectX500Principal().getName()));
      if (value.equals(ocspCN))
        return new X509Cert(cert.getCertificate());
    }
    CertificateNotFoundException exception =
        new CertificateNotFoundException("Certificate for " + ocspCN + " not found in TSL");
    logger.error(exception.getMessage());
    throw exception;
  }

  private String getOCSPCommonName() {
    logger.debug("");
    RespID responderId = origin.getOCSPSource().getContainedOCSPResponses().get(0).getResponderId();
    String commonName = getCN(responderId.toASN1Object().getName());
    logger.debug("OCSP common name: " + commonName);
    return commonName;
  }

  private String getCN(X500Name x500Name) {
    logger.debug("");
    String name = x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.3"))[0].getTypesAndValues()[0].getValue().toString();
    logger.debug("Common name: " + name);
    return name;
  }

  @Override
  @Deprecated
  public String getPolicy() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public String getPostalCode() {
    logger.debug("");
    return signerLocation == null ? null : signerLocation.getPostalCode();
  }

  @Override
  public Date getOCSPResponseCreationTime() {
    logger.debug("");
    Date date = origin.getOCSPSource().getContainedOCSPResponses().get(0).getProducedAt();
    logger.debug("Produced at date: " + date);
    return date;
  }

  @Override
  @Deprecated
  public Date getProducedAt() {
    return getOCSPResponseCreationTime();
  }

  @Override
  public Date getTimeStampCreationTime() {
    logger.debug("");
    List<TimestampToken> signatureTimestamps = origin.getSignatureTimestamps();
    if (signatureTimestamps.size() == 0) {
      return null;
    }
    Date date = signatureTimestamps.get(0).getGenerationTime();
    logger.debug("Time stamp creation time: " + date);
    return date;
  }

  @Override
  public Date getTrustedSigningTime() {
    if(getProfile() == B_BES) {
      return null;
    }
    //TODO trusted signing time should be taken based on the profile: LT_TM should return OCSP response creation time and LT should return TS creation time when getProfile() gets fixed.
    Date timeStampCreationTime = getTimeStampCreationTime();
    if(timeStampCreationTime != null) {
      return timeStampCreationTime;
    }
    return getOCSPResponseCreationTime();
  }

  @Override
  public SignatureProfile getProfile() {
    //FIXME LT_TM and LT both return LT, because they both have XAdES-BASELINE-LT. LT_TM should return LT_TM.
    SignatureLevel dataFoundUpToLevel = origin.getDataFoundUpToLevel();
    logger.debug("getting profile for: " + dataFoundUpToLevel);
    return signatureProfileMap.get(dataFoundUpToLevel);
  }

  @Override
  public String getSignatureMethod() {
    logger.debug("");

    String xmlId = origin.getDigestAlgorithm().getXmlId();
    logger.debug("Signature method: " + xmlId);
    return xmlId;
  }

  @Override
  public List<String> getSignerRoles() {
    logger.debug("");
    String[] claimedSignerRoles = origin.getClaimedSignerRoles();
    return claimedSignerRoles == null ? null : Arrays.asList(claimedSignerRoles);
  }

  @Override
  public X509Cert getSigningCertificate() {
    logger.debug("");
    return new X509Cert(origin.getSigningCertificateToken().getCertificate());
  }

  @Override
  public Date getClaimedSigningTime() {
    logger.debug("");
    Date signingTime = origin.getSigningTime();
    logger.debug("Signing time: " + signingTime);
    return signingTime;
  }

  @Override
  public Date getSigningTime() {
    return getClaimedSigningTime();
  }

  @Override
  @Deprecated
  public URI getSignaturePolicyURI() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public String getStateOrProvince() {
    logger.debug("");
    return signerLocation == null ? null : signerLocation.getStateOrProvince();
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    logger.debug("");
    if (origin.getSignatureTimestamps() == null || origin.getSignatureTimestamps().size() == 0) {
      CertificateNotFoundException exception = new CertificateNotFoundException("TimeStamp certificate not found");
      logger.error(exception.getMessage());
      throw exception;
    }
    return new X509Cert(origin.getSignatureTimestamps().get(0).getIssuerToken().getCertificate());
  }

  @Override
  public List<DigiDoc4JException> validate() {
    logger.debug("");
    return validationErrors;
  }

  @Override
  public byte[] getAdESSignature() {
    logger.debug("");
    Document document = createDocument(ASiCNamespaces.ASiC, ASiCService.ASICS_NS, origin.getSignatureElement());
    return DSSXMLUtils.transformDomToByteArray(document);
  }

  @Override
  @Deprecated
  public byte[] getRawSignature() {
    return getAdESSignature();
  }

  XAdESSignature getOrigin() {
    return origin;
  }
}
