/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.ValidatableSignature;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidator;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidatorFactory;
import org.digidoc4j.impl.asic.xades.validation.XadesValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;
import java.util.List;

/**
 * Created by Andrei on 29.11.2017.
 */
public class AsicSignature implements Signature, ValidatableSignature {

  private static final Logger logger = LoggerFactory.getLogger(AsicSignature.class);
  private transient ValidationResult validationResult;
  private XadesSignature xadesSignature;
  private SignatureValidator validator;
  private DSSDocument signatureDocument;
  private Configuration configuration;

  /**
   * Asic signature constructor.
   *
   * @param xadesSignature XADES signature
   * @param validator      signature validator
   */
  public AsicSignature(XadesSignature xadesSignature, SignatureValidator validator) {
    this.xadesSignature = xadesSignature;
    this.validator = validator;
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
  public String getUniqueId() {
    return xadesSignature.getUniqueId();
  }

  @Override
  public byte[] getOCSPNonce() {
    return xadesSignature.getOCSPNonce();
  }

  @Override
  public X509Cert getOCSPCertificate() {
    return xadesSignature.getOCSPCertificate();
  }

  @Override
  public String getPostalCode() {
    return xadesSignature.getPostalCode();
  }


  /**
   * This method returns Date object, it can be null.
   *
   * @return Date
   */
  @Override
  public Date getOCSPResponseCreationTime() {
    return xadesSignature.getOCSPResponseCreationTime();
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

  /**
   * This method returns Date object, it can be null.
   *
   * @return Date
   */
  @Override
  public Date getClaimedSigningTime() {
    return xadesSignature.getSigningTime();
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
  public ValidationResult validateSignature() {
    logger.debug("Validating signature");
    if (validationResult == null) {
      validationResult = validator.extractResult();
      logger.info(
              "Signature has {} validation errors and {} warnings",
              validationResult.getErrors().size(), validationResult.getWarnings().size()
      );
    } else {
      logger.debug(
              "Using cached signature validation result. Signature has {} validation errors and {} warnings",
              validationResult.getErrors().size(), validationResult.getWarnings().size()
      );
    }
    return validationResult;
  }

  @Override
  public ValidationResult validateSignatureAt(Date validationTime) {
    logger.debug("Validating signature @ {}", validationTime);
    XadesSignatureValidatorFactory validatorFactory = new XadesSignatureValidatorFactory();
    validatorFactory.setConfiguration(getConfiguration());
    validatorFactory.setSignature(xadesSignature);
    validatorFactory.setValidationTime(validationTime);
    SignatureValidator validatorAtTime = validatorFactory.create();
    ValidationResult validationResultAtTime = validatorAtTime.extractResult();
    logger.info(
            "Signature has {} validation errors and {} warnings @ {}",
            validationResultAtTime.getErrors().size(), validationResultAtTime.getWarnings().size(), validationTime
    );
    return validationResultAtTime;
  }

  @Override
  public byte[] getAdESSignature() {
    logger.debug("Getting full XAdES signature byte array");
    try {
      return IOUtils.toByteArray(signatureDocument.openStream());
    } catch (IOException e) {
      throw new TechnicalException("Error parsing xades signature: " + e.getMessage(), e);
    }
  }

  /**
   * This method returns XadesSignature object.
   *
   * @return xades signature.
   */
  public XadesSignature getOrigin() {
    return xadesSignature;
  }

  /**
   * Set signature document.
   *
   * @param signatureDocument
   */
  public void setSignatureDocument(DSSDocument signatureDocument) {
    this.signatureDocument = signatureDocument;
  }

  /**
   * This method returns validation result (XadesValidationResult object).
   *
   * @return XadesValidationResult.
   */
  public XadesValidationResult getDssValidationReport() {
    return xadesSignature.validate();
  }

  /**
   * This method returns signature document (SignatureDocument object).
   *
   * @return DSSDocument.
   */
  public DSSDocument getSignatureDocument() {
    return signatureDocument;
  }

  /**
   * Gets Signature Digest Algorithm
   *
   * @return DigestAlgorithm
   */
  public DigestAlgorithm getSignatureDigestAlgorithm() {
    return xadesSignature.getDssSignature().getDigestAlgorithm();
  }

  /**
   * Setter for Configuration
   *
   * @param configuration
   */
  public void setConfiguration(Configuration configuration){
    this.configuration = configuration;
  }

  /**
   * Getter for Configuration

   * @return Configuration
   */
  public Configuration getConfiguration(){
    return this.configuration;
  }
}
