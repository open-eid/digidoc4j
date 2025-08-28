/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzer;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NonExtendableSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.AiaSourceFactory;
import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.impl.asic.DetachedContentCreator;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.B_EPES;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.digidoc4j.SignatureProfile.LT_TM;
import static org.digidoc4j.SignatureProfile.T;

public class SignatureExtendingValidator {

  private static final Logger logger = LoggerFactory.getLogger(SignatureExtendingValidator.class);
  private static final Map<SignatureProfile, Set<SignatureProfile>> possibleExtensions = new HashMap<>(6);

  private final CertificateVerifier certificateVerifier;
  private final List<DSSDocument> detachedContentList;

  static { //TODO DD4J-1042
    possibleExtensions.put(B_BES, new HashSet<>(asList(T, LT, LTA)));
    possibleExtensions.put(B_EPES, emptySet());
    possibleExtensions.put(LT, singleton(LTA));
    possibleExtensions.put(T, new HashSet<>(asList(LT, LTA)));
    possibleExtensions.put(LT_TM, emptySet());
    possibleExtensions.put(LTA, singleton(LTA));
  }

  /**
   * Create signature validator for an ASiC container
   *
   * @param dataFiles data files in the container
   * @param configuration the configuration used by the container
   */
  public SignatureExtendingValidator(Collection<DataFile> dataFiles, Configuration configuration) {
    DetachedContentCreator detachedContentCreator;
    try {
      detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    } catch (Exception e) {
      throw new TechnicalException("Failed to process datafiles in the container", e);
    }
    detachedContentList = detachedContentCreator.getDetachedContentList();

    certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setCrlSource(null); //Disable CRL checks
    certificateVerifier.setTrustedCertSources(configuration.getTSL());
    certificateVerifier.setAIASource(new AiaSourceFactory(configuration).create());
  }

  /**
   * Checks whether the signature can be extended to target profile.
   * Both DigiDoc4j's and DSS's validations must pass to extend a signature.
   *
   * @param signature signature to extend
   * @param targetProfile target profile
   * @throws DigiDoc4JException if the signature can not be extended to target profile
   * @see SignatureProfile
   */
  public void validateExtendability(Signature signature, SignatureProfile targetProfile) {
    try {
      validateProfileExtendability(signature, targetProfile);
      validateSignatureWithDss(signature);
    } catch (DigiDoc4JException e) {
      throw e;
    // Wrap other exception types into DigiDoc4JException or its subclass NonExtendableSignatureException
    } catch (AlertException | DSSException e) {
      throw new NonExtendableSignatureException("Validating the signature with DSS failed", e);
    } catch (Exception e) {
      throw new DigiDoc4JException("Unexpected error while validating the signature with DSS", e);
    }
  }

  /**
   * Checks whether DigiDoc4j's rules allow all the signatures to be extended to target profile.
   *
   * @param signatures signatures to extend
   * @param targetProfile target profile
   * @throws NotSupportedException if at least 1 signature can not be extended to target profile
   * @see SignatureProfile
   */
  public static void validateProfileExtendability(List<Signature> signatures, SignatureProfile targetProfile) {
    logger.debug("Validating if it's possible to extend all the signatures to {}", targetProfile);
    for (Signature signature : signatures) {
      validateProfileExtendability(signature, targetProfile);
    }
  }

  private static void validateProfileExtendability(Signature signature, SignatureProfile targetProfile) {
    if (!canExtendSignatureToProfile(signature, targetProfile)) {
      String message = "It is not possible to extend " + signature.getProfile() + " signature to " + targetProfile + ".";
      logger.error(message);
      throw new NotSupportedException(message);
    }
  }

  private void validateSignatureWithDss(Signature signature) {
    AsicSignature asicSignature = (AsicSignature) signature;
    DSSDocument signatureDocument = asicSignature.getSignatureDocument();
    XAdESSignature dssSignature = asicSignature.getOrigin().getDssSignature();
    assertSignatureValid(dssSignature, signatureDocument);
    assertSignatureIntact(dssSignature);
  }

  private void assertSignatureValid(final AdvancedSignature signature, final DSSDocument signatureDocument) {
    // Copied from eu.europa.esig.dss.xades.signature.XAdESLevelBaselineT#extendSignatures from DSS library
    DocumentAnalyzer documentAnalyzer = new XMLDocumentAnalyzer(signatureDocument);
    documentAnalyzer.setCertificateVerifier(certificateVerifier);
    documentAnalyzer.setDetachedContents(detachedContentList);
    // It is important that CompleteValidationContextExecutor is used in order to catch all invalid signatures
    documentAnalyzer.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);
    // getValidationData() throws AlertException in case of validation failure
    documentAnalyzer.getValidationData(Collections.singletonList(signature));
  }

  private void assertSignatureIntact(final AdvancedSignature signature) {
    XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
    // Use dummy signature parameters for requirements checker because signature parameters cannot be null
    SignatureRequirementsChecker signatureRequirementsChecker = new SignatureRequirementsChecker(certificateVerifier, signatureParameters);
    // assertSignaturesValid() throws AlertException in case of validation failure
    signatureRequirementsChecker.assertSignaturesValid(Collections.singletonList(signature));
  }

  private static boolean canExtendSignatureToProfile(Signature signature, SignatureProfile targetProfile) {
    return possibleExtensions.getOrDefault(signature.getProfile(), emptySet()).contains(targetProfile);
  }
}
