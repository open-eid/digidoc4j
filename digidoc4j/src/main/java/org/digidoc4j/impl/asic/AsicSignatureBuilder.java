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

import eu.europa.esig.dss.model.InMemoryDocument;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataToSign;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureFinalizerBuilder;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.utils.CertificateUtils;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Signature builder for Asic container.
 */
public class AsicSignatureBuilder extends SignatureBuilder {

  private static final Logger logger = LoggerFactory.getLogger(AsicSignatureBuilder.class);
  private SignatureFinalizer signatureFinalizer;

  @Override
  protected Signature invokeSigningProcess() {
    logger.info("Signing asic container");
    signatureParameters.setSigningCertificate(signatureToken.getCertificate());
    byte[] dataToSign = getSignatureFinalizer().getDataToBeSigned();
    byte[] signatureValue = null;
    try {
      signatureValue = signatureToken.sign(signatureParameters.getDigestAlgorithm(), dataToSign);
      return finalizeSignature(signatureValue);
    } catch (TechnicalException e) {
      String dataToSignHex = Helper.bytesToHex(dataToSign, AsicSignatureFinalizer.HEX_MAX_LENGTH);
      String signatureValueHex = signatureValue == null ? null : Helper.bytesToHex(signatureValue, AsicSignatureFinalizer.HEX_MAX_LENGTH);
      logger.warn("PROBLEM with signing: {} -> {}", dataToSignHex, signatureValueHex);
      throw e;
    }
  }

  @Override
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException {
    SignatureFinalizer signatureFinalizer = getSignatureFinalizer();
    byte[] dataToBeSigned = signatureFinalizer.getDataToBeSigned();
    validateSignatureCompatibilityWithContainer();
    return new DataToSign(dataToBeSigned, signatureFinalizer);
  }

  @Override
  public Signature openAdESSignature(byte[] signatureDocument) {
    if (signatureDocument == null) {
      logger.error("Signature cannot be empty");
      throw new InvalidSignatureException();
    }
    InMemoryDocument document = new InMemoryDocument(signatureDocument);
    return getSignatureFinalizer().createSignature(document);
  }

  /**
   * @deprecated use {@link SignatureBuilder#invokeSigningProcess()} or {@link SignatureFinalizer#finalizeSignature(byte[] signatureValue)} instead.
   */
  @Deprecated
  public Signature finalizeSignature(byte[] signatureValue) {
    return getSignatureFinalizer().finalizeSignature(signatureValue);
  }

  public Configuration getConfiguration() {
    return container.getConfiguration();
  }

  private SignatureFinalizer getSignatureFinalizer() {
    if (signatureFinalizer == null) {
      populateSignatureParameters();
      this.signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);
    }
    return signatureFinalizer;
  }

  private void populateSignatureParameters() {
    populateDigestAlgorithm();
    populateEncryptionAlgorithm();
    populateSignatureProfile();
  }

  private void populateDigestAlgorithm() {
    if (signatureParameters.getDigestAlgorithm() == null) {
      signatureParameters.setDigestAlgorithm(getConfiguration().getSignatureDigestAlgorithm());
    }
  }

  private void populateEncryptionAlgorithm() {
    if (signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA || CertificateUtils.isEcdsaCertificate(signatureParameters.getSigningCertificate())) {
      signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
    } else {
      signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
    }
  }

  private void populateSignatureProfile() {
    if (signatureParameters.getSignatureProfile() == null) {
      signatureParameters.setSignatureProfile(getConfiguration().getSignatureProfile());
    }
  }

  protected void validateSignatureCompatibilityWithContainer() {
    // Do nothing
  }
}
