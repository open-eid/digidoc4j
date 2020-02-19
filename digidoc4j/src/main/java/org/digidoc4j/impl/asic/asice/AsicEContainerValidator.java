/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.asice;

import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.digidoc4j.Configuration;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateSignatureFilesException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.asic.AsicContainerValidationResult;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.impl.asic.AsicValidationReportBuilder;
import org.digidoc4j.impl.asic.manifest.ManifestErrorMessage;
import org.digidoc4j.impl.asic.manifest.ManifestParser;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidationData;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidationTask;
import org.digidoc4j.impl.asic.xades.validation.ThreadPoolManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/**
 * ASIC-E container validator
 */
public class AsicEContainerValidator {

  private static final Logger logger = LoggerFactory.getLogger(AsicEContainerValidator.class);

  protected List<DigiDoc4JException> errors = new ArrayList<>();
  protected List<DigiDoc4JException> warnings = new ArrayList<>();

  private AsicParseResult containerParseResult;
  private boolean validateManifest;
  private List<SignatureValidationData> signatureValidationData = new ArrayList<>();
  private List<DigiDoc4JException> manifestErrors;
  private List<DigiDoc4JException> containerErrors = new ArrayList<>();
  private ThreadPoolManager threadPoolManager;

  /**
   * @param configuration configuration
   */
  public AsicEContainerValidator(Configuration configuration) {
    threadPoolManager = new ThreadPoolManager(configuration);
    validateManifest = false;
  }

  /**
   * @param containerParseResult parse result
   * @param configuration        configuration
   */
  public AsicEContainerValidator(AsicParseResult containerParseResult, Configuration configuration) {
    this(containerParseResult, configuration, true);
  }

  /**
   * @param containerParseResult parse result
   * @param configuration        configuration context
   * @param validateManifest     validate manifest
   */
  public AsicEContainerValidator(AsicParseResult containerParseResult, Configuration configuration,
                                 boolean validateManifest) {
    this.containerParseResult = containerParseResult;
    this.threadPoolManager = new ThreadPoolManager(configuration);
    this.validateManifest = validateManifest;
  }

  /**
   * @param signatures list of signatures
   * @return validation result
   */
  public ContainerValidationResult validate(List<Signature> signatures) {
    logger.debug("Validating container");
    validateSignatures(signatures);
    extractManifestErrors(signatures);
    extractContainerErrors(signatures);
    AsicContainerValidationResult result = createValidationResult();
    logger.info("Is container valid: " + result.isValid());
    return result;
  }

  protected void validateSignatures(List<Signature> signatures) {
    List<Future<SignatureValidationData>> validationData = startSignatureValidationInParallel(signatures);
    extractValidatedSignatureErrors(validationData);
  }

  protected List<Future<SignatureValidationData>> startSignatureValidationInParallel(List<Signature> signatures) {
    List<Future<SignatureValidationData>> futures = new ArrayList<>();
    for (Signature signature : signatures) {
      SignatureValidationTask validationExecutor = new SignatureValidationTask(signature);
      Future<SignatureValidationData> validationDataFuture = threadPoolManager.submit(validationExecutor);
      futures.add(validationDataFuture);
    }
    return futures;
  }

  protected void extractValidatedSignatureErrors(List<Future<SignatureValidationData>> validationFutures) {
    logger.debug("Extracting errors from the signatures");
    for (Future<SignatureValidationData> validationFuture : validationFutures) {
      try {
        SignatureValidationData validationData = validationFuture.get();
        extractSignatureErrors(validationData);
      } catch (InterruptedException | ExecutionException e) {
        logger.error("Error validating signatures on multiple threads: " + e.getMessage());
        throw new TechnicalException("Error validating signatures on multiple threads: " + e.getMessage(), e);
      }
    }
  }

  /**
   * @param validateManifest validate manifest flag
   */
  public void setValidateManifest(boolean validateManifest) {
    this.validateManifest = validateManifest;
  }

  protected void extractSignatureErrors(SignatureValidationData validationData) {
    logger.debug("Extracting signature errors for signature " + validationData.getSignatureId());
    signatureValidationData.add(validationData);
    ValidationResult validationResult = validationData.getValidationResult();
    errors.addAll(validationResult.getErrors());
    warnings.addAll(validationResult.getWarnings());
  }

  protected void extractManifestErrors(List<Signature> signatures) {
    logger.debug("Extracting manifest errors");
    manifestErrors = findManifestErrors(signatures);
    errors.addAll(manifestErrors);
    containerErrors.addAll(manifestErrors);
  }

  protected AsicContainerValidationResult createValidationResult() {
    AsicValidationReportBuilder reportBuilder = new AsicValidationReportBuilder(signatureValidationData,
        manifestErrors);
    AsicContainerValidationResult result = new AsicContainerValidationResult();
    result.setErrors(errors);
    result.setWarnings(warnings);
    result.setContainerErrors(containerErrors);
    result.generate(reportBuilder);
    return result;
  }

  protected List<DigiDoc4JException> findManifestErrors(List<Signature> signatures) {
    if (!validateManifest || containerParseResult == null) {
      return Collections.emptyList();
    }

    List<DigiDoc4JException> manifestExceptions = new ArrayList<>();
    ManifestParser manifestParser = containerParseResult.getManifestParser();
    if (manifestParser == null || !manifestParser.containsManifestFile()) {
      logger.error("Container is missing manifest.xml");
      manifestExceptions.add(new UnsupportedFormatException("Container does not contain a manifest file"));
      return manifestExceptions;
    }

    List<DSSDocument> detachedContents = containerParseResult.getDetachedContents();
    List<ManifestErrorMessage> manifestErrorMessageList = new ManifestValidator(manifestParser, detachedContents,
        signatures).validateDocument();
    for (ManifestErrorMessage manifestErrorMessage : manifestErrorMessageList) {
      manifestExceptions.add(
          new DigiDoc4JException(manifestErrorMessage.getErrorMessage(), manifestErrorMessage.getSignatureId()));
    }
    return manifestExceptions;
  }

  private void extractContainerErrors(List<Signature> signatures) {
    List<DigiDoc4JException> signatureNameErrors = findDuplicateSignatureNameErrors(signatures);
    containerErrors.addAll(signatureNameErrors);
    errors.addAll(signatureNameErrors);
  }

  private List<DigiDoc4JException> findDuplicateSignatureNameErrors(List<Signature> signatures) {
    MultiValuedMap<String, DSSDocument> signatureDocumentNames = new ArrayListValuedHashMap<>();
    for (Signature signature : signatures) {
      DSSDocument signatureDocument = ((AsicSignature) signature).getSignatureDocument();
      if (signatureDocument.getName() != null) {
        signatureDocumentNames.put(signatureDocument.getName(), signatureDocument);
      }
    }

    List<DigiDoc4JException> fileNameErrors = new ArrayList<>();
    for (String signatureDocumentName : signatureDocumentNames.keySet()) {
      if (signatureDocumentNames.get(signatureDocumentName).size() > 1) {
        DuplicateSignatureFilesException error = new DuplicateSignatureFilesException("Duplicate signature files: " + signatureDocumentName);
        fileNameErrors.add(error);
      }
    }
    return fileNameErrors;
  }
}
