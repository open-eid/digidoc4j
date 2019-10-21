/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import org.digidoc4j.exceptions.DataFileMissingException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.AsicSignatureFinalizer;
import org.digidoc4j.utils.CertificateUtils;
import org.digidoc4j.utils.Helper;
import org.digidoc4j.utils.PolicyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;

public class DetachedXadesSignatureBuilder {

  private static final Logger logger = LoggerFactory.getLogger(DetachedXadesSignatureBuilder.class);

  private List<DataFile> dataFiles = new ArrayList<>();
  private SignatureParameters signatureParameters = new SignatureParameters();
  private Configuration configuration;
  private SignatureToken signatureToken;
  private SignatureFinalizer signatureFinalizer;

  /**
   * Specify configuration for the builder.
   *
   * @param configuration configuration to be used for creating the signature.
   * @return builder for creating a signature.
   */
  public static DetachedXadesSignatureBuilder withConfiguration(Configuration configuration) {
    DetachedXadesSignatureBuilder builder = new DetachedXadesSignatureBuilder();
    builder.setConfiguration(configuration);
    return builder;
  }

  /**
   * Add a data file to builder.
   *
   * @param dataFile data file to be added to the builder.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withDataFile(DataFile dataFile) {
    dataFiles.add(dataFile);
    return this;
  }

  /**
   * Set a signing certificate to be used when creating data to be signed.
   *
   * @param certificate X509 signer's certificate.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSigningCertificate(X509Certificate certificate) {
    signatureParameters.setSigningCertificate(certificate);
    return this;
  }

  /**
   * Set signature digest algorithm used to generate a signature.
   *
   * @param digestAlgorithm signature digest algorithm.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSignatureDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    signatureParameters.setDigestAlgorithm(digestAlgorithm);
    return this;
  }

  /**
   * Set a city to the signature production place.
   *
   * @param cityName city to use on the signature production place.
   * @return builder for creating a signature
   */
  public DetachedXadesSignatureBuilder withCity(String cityName) {
    signatureParameters.setCity(cityName);
    return this;
  }

  /**
   * Set a state or province to the signature production place.
   *
   * @param stateOrProvince name of the state or province on the signature production place.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withStateOrProvince(String stateOrProvince) {
    signatureParameters.setStateOrProvince(stateOrProvince);
    return this;
  }

  /**
   * Set a postal code to the signature production place.
   *
   * @param postalCode postal code on the signature production place.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withPostalCode(String postalCode) {
    signatureParameters.setPostalCode(postalCode);
    return this;
  }

  /**
   * Set a country name to the signature production place.
   *
   * @param country name of the country on the signature production place.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withCountry(String country) {
    signatureParameters.setCountry(country);
    return this;
  }

  /**
   * Set roles to the signer.
   *
   * @param roles list of roles of a signer.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withRoles(String... roles) {
    if (signatureParameters.getRoles() == null) {
      signatureParameters.setRoles(asList(roles));
    } else {
      signatureParameters.getRoles().addAll(asList(roles));
    }
    return this;
  }

  /**
   * Set signature ID.
   *
   * @param signatureId signature id.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSignatureId(String signatureId) {
    signatureParameters.setXmlDigitalSignatureId(signatureId);
    return this;
  }

  /**
   * Set encryption algorithm to be used in the signing process.
   *
   * @param encryptionAlgorithm encryption algorithm.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
    signatureParameters.setEncryptionAlgorithm(encryptionAlgorithm);
    return this;
  }

  /**
   * Set a signature profile: Time Mark, Time Stamp, Archive Time Stamp or no profile. Default is Time Stamp.
   *
   * @param signatureProfile signature profile.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSignatureProfile(SignatureProfile signatureProfile) {
    Policy policyDefinedByUser = signatureParameters.getPolicy();
    if (policyDefinedByUser != null && PolicyUtils.areAllPolicyValuesDefined(policyDefinedByUser)
        && signatureProfile != SignatureProfile.LT_TM) {
      logger.debug("policyDefinedByUser:" + policyDefinedByUser.toString());
      logger.debug("signatureProfile:" + signatureProfile.toString());
      throw new NotSupportedException("Can't define signature policy if it's not LT_TM signature profile ");
    }
    signatureParameters.setSignatureProfile(signatureProfile);
    return this;
  }

  /**
   * Set signature policy parameters. Define signature profile first.
   *
   * @param signaturePolicy with defined parameters.
   * @return SignatureBuilder
   */
  public DetachedXadesSignatureBuilder withOwnSignaturePolicy(Policy signaturePolicy) {
    if (signatureParameters.getSignatureProfile() != null
        && signatureParameters.getSignatureProfile() != SignatureProfile.LT_TM) {
      throw new NotSupportedException("Can't define signature policy if it's not LT_TM signature profile. Define it first. ");
    }
    signatureParameters.setPolicy(signaturePolicy);
    return this;
  }

  /**
   * Set signature token to be used in the signing process.
   *
   * @param signatureToken signature token.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSignatureToken(SignatureToken signatureToken) {
    this.signatureToken = signatureToken;
    return this;
  }

  /**
   * Creates data to be signed externally.
   * <p>
   * If the signing process involves signing the container externally (e.g. signing in the Web by a browser plugin),
   * then {@link DataToSign} provides necessary data for creating a signature externally.
   *
   * @return data to be signed externally.
   * @throws SignerCertificateRequiredException signer certificate must be provided using
   * {@link DetachedXadesSignatureBuilder#withSigningCertificate(X509Certificate)}
   * @throws DataFileMissingException builder must have at least one data file to be signed.
   */
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, DataFileMissingException {
    if (signatureParameters.getSigningCertificate() == null) {
      logger.error("Cannot invoke signing without signing certificate. Add 'withSigningCertificate()' method call or " +
          "call" +
          " 'withSignatureToken() instead.'");
      throw new SignerCertificateRequiredException();
    }
    SignatureFinalizer signatureFinalizer = getSignatureFinalizer();
    byte[] dataToBeSigned = signatureFinalizer.getDataToBeSigned();
    return new DataToSign(dataToBeSigned, signatureFinalizer);
  }

  public Signature finalizeSignature(byte[] signatureValue) {
    return getSignatureFinalizer().finalizeSignature(signatureValue);
  }

  /**
   * Invokes a signing process on the container with a signature token (See {@link SignatureToken}).
   * Signature token must be provided with {@link DetachedXadesSignatureBuilder#withSignatureToken(SignatureToken)}.
   *
   * @return a new signature on the container.
   * @throws SignatureTokenMissingException if signature token is not provided with
   * {@link DetachedXadesSignatureBuilder#withSignatureToken(SignatureToken)}
   * @see SignatureToken
   */
  public Signature invokeSigning() throws SignatureTokenMissingException {
    if (signatureToken == null) {
      logger.error("Cannot invoke signing without signature token. Add 'withSignatureToken()' method call or call 'buildDataToSign() instead.'");
      throw new SignatureTokenMissingException();
    }
    return invokeSigningProcess();
  }

  /**
   * Creates signature object from XadES signature xml.
   *
   * @param signatureDocument XadES signature xml bytes.
   * @return builder for creating a signature.
   */
  public Signature openAdESSignature(byte[] signatureDocument) {
    if (signatureDocument == null) {
      logger.error("Signature cannot be empty");
      throw new InvalidSignatureException();
    }
    InMemoryDocument document = new InMemoryDocument(signatureDocument);
    return getSignatureFinalizer().createSignature(document);
  }

  protected Signature invokeSigningProcess() {
    logger.info("Creating Xades Signature");
    signatureParameters.setSigningCertificate(signatureToken.getCertificate());
    byte[] dataToSign = getSignatureFinalizer().getDataToBeSigned();
    Signature result = null;
    byte[] signatureValue = null;
    try {
      signatureValue = signatureToken.sign(signatureParameters.getDigestAlgorithm(), dataToSign);
      result = finalizeSignature(signatureValue);
    } catch (TechnicalException e) {
      String dataToSignHex = Helper.bytesToHex(dataToSign, AsicSignatureFinalizer.HEX_MAX_LENGTH);
      String signatureValueHex = signatureValue == null ? null : Helper.bytesToHex(signatureValue, AsicSignatureFinalizer.HEX_MAX_LENGTH);
      logger.warn("PROBLEM with signing: {} -> {}", dataToSignHex, signatureValueHex);
    }
    return result;
  }

  protected void setConfiguration(Configuration configuration) {
    this.configuration = configuration;
  }

  private SignatureFinalizer getSignatureFinalizer() {
    if (signatureFinalizer == null) {
      populateSignatureParameters();
      if (SignatureContainerMatcherValidator.isBDocOnlySignature(signatureParameters.getSignatureProfile())) {
        signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(dataFiles, signatureParameters, configuration, Container.DocumentType.BDOC);
      } else {
        signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(dataFiles, signatureParameters, configuration, Container.DocumentType.ASICE);
      }
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
      signatureParameters.setDigestAlgorithm(configuration.getSignatureDigestAlgorithm());
    }
  }

  private void populateEncryptionAlgorithm() {
    if (signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA || CertificateUtils.isEcdsaCertificate(signatureParameters.getSigningCertificate())) {
      logger.debug("Using ECDSA encryption algorithm");
      signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
    } else {
      signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
    }
  }

  private void populateSignatureProfile() {
    if (signatureParameters.getSignatureProfile() == null) {
      signatureParameters.setSignatureProfile(configuration.getSignatureProfile());
    }
  }
}
