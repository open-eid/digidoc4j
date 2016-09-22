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

import java.net.URI;
import java.util.Date;
import java.util.List;

import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.impl.bdoc.xades.validation.SignatureValidator;
import org.digidoc4j.impl.bdoc.xades.validation.XadesValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * BDoc signature implementation.
 */
public class BDocSignature implements Signature {
  private static final Logger logger = LoggerFactory.getLogger(BDocSignature.class);
  private SignatureValidationResult validationResult;
  private XadesSignature xadesSignature;
  private SignatureValidator validator;
  private DSSDocument signatureDocument;

  public BDocSignature(XadesSignature xadesSignature, SignatureValidator validator) {
    this.xadesSignature = xadesSignature;
    this.validator = validator;
    logger.debug("New BDoc signature created");
  }

  @Override
  public String getCity() {
    return xadesSignature.getCity();
  }

  @Override
  public String getCountryName() {
    return xadesSignature.getCountryName();
  }

  @Override
  public String getId() {
    return xadesSignature.getId();
  }

  @Override
  public byte[] getOCSPNonce() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public X509Cert getOCSPCertificate() {
    return xadesSignature.getOCSPCertificate();
  }

  @Override
  @Deprecated
  public String getPolicy() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public String getPostalCode() {
    return xadesSignature.getPostalCode();
  }

  @Override
  public Date getOCSPResponseCreationTime() {
    return xadesSignature.getOCSPResponseCreationTime();
  }

  @Override
  @Deprecated
  public Date getProducedAt() {
    return getOCSPResponseCreationTime();
  }

  @Override
  public Date getTimeStampCreationTime() {
    return xadesSignature.getTimeStampCreationTime();
  }

  /**
   * Trusted signing time should be taken based on the profile:
   * BES should return null,
   * LT_TM should return OCSP response creation time and
   * LT should return Timestamp creation time.
   *
   * @return signing time backed by a trusted service (not just a user's computer clock time).
   */
  @Override
  public Date getTrustedSigningTime() {
    return xadesSignature.getTrustedSigningTime();
  }

  @Override
  public SignatureProfile getProfile() {
    return xadesSignature.getProfile();
  }

  @Override
  public String getSignatureMethod() {
    return xadesSignature.getSignatureMethod();
  }

  @Override
  public List<String> getSignerRoles() {
    return xadesSignature.getSignerRoles();
  }

  @Override
  public X509Cert getSigningCertificate() {
    return xadesSignature.getSigningCertificate();
  }

  @Override
  public Date getClaimedSigningTime() {
    return xadesSignature.getSigningTime();
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
    return xadesSignature.getStateOrProvince();
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    return xadesSignature.getTimeStampTokenCertificate();
  }

  @Override
  public SignatureValidationResult validateSignature() {
    logger.debug("Validating signature");
    if (validationResult == null) {
      validationResult = validator.extractValidationErrors();
      logger.info("Signature has " + validationResult.getErrors().size() + " validation errors and " + validationResult.getWarnings().size() + " warnings");
    } else {
      logger.debug("Using existing validation errors with " + validationResult.getErrors().size() + " validation errors and " + validationResult.getWarnings().size() + " warnings");
    }
    return validationResult;
  }

  @Override
  @Deprecated
  public List<DigiDoc4JException> validate() {
    return validateSignature().getErrors();
  }

  @Override
  public byte[] getAdESSignature() {
    logger.debug("Getting full XAdES signature byte array");
    return xadesSignature.getAdESSignature();
  }

  @Override
  @Deprecated
  public byte[] getRawSignature() {
    return getAdESSignature();
  }

  public XadesSignature getOrigin() {
    return xadesSignature;
  }

  public void setSignatureDocument(DSSDocument signatureDocument) {
    this.signatureDocument = signatureDocument;
  }

  public XadesValidationResult getDssValidationReport() {
    return xadesSignature.validate();
  }

  public DSSDocument getSignatureDocument() {
    return signatureDocument;
  }

  DigestAlgorithm getSignatureDigestAlgorithm() {
    return xadesSignature.getDssSignature().getDigestAlgorithm();
  }
}
