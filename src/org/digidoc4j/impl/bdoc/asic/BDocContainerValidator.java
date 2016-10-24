/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.asic;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.digidoc4j.Configuration;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.bdoc.BDocValidationReportBuilder;
import org.digidoc4j.impl.bdoc.BDocValidationResult;
import org.digidoc4j.impl.bdoc.manifest.ManifestParser;
import org.digidoc4j.impl.bdoc.manifest.ManifestValidator;
import org.digidoc4j.impl.bdoc.xades.validation.SignatureValidationData;
import org.digidoc4j.impl.bdoc.xades.validation.SignatureValidationTask;
import org.digidoc4j.impl.bdoc.xades.validation.ThreadPoolManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

public class BDocContainerValidator implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(BDocContainerValidator.class);
  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();
  private AsicParseResult containerParseResult;
  private boolean validateManifest;
  private List<SignatureValidationData> signatureValidationData = new ArrayList<>();
  private List<DigiDoc4JException> manifestErrors;
  private ThreadPoolManager threadPoolManager;

  public BDocContainerValidator(Configuration configuration) {
    threadPoolManager = new ThreadPoolManager(configuration);
    validateManifest = false;
  }

  public BDocContainerValidator(AsicParseResult containerParseResult, Configuration configuration) {
    this.containerParseResult = containerParseResult;
    threadPoolManager = new ThreadPoolManager(configuration);
    validateManifest = true;
  }

  public ValidationResult validate(List<Signature> signatures) {
    logger.debug("Validating container");
    validateSignatures(signatures);
    extractManifestErrors(signatures);
    BDocValidationResult result = createValidationResult();
    logger.info("Is container valid: " + result.isValid());
    return result;
  }

  private void validateSignatures(List<Signature> signatures) {
    List<Future<SignatureValidationData>> validationData = startSignatureValidationInParallel(signatures);
    extractValidatedSignatureErrors(validationData);
  }

  private List<Future<SignatureValidationData>> startSignatureValidationInParallel(List<Signature> signatures) {
    List<Future<SignatureValidationData>> futures = new ArrayList<>();
    for (Signature signature : signatures) {
      SignatureValidationTask validationExecutor = new SignatureValidationTask(signature);
      Future<SignatureValidationData> validationDataFuture = threadPoolManager.submit(validationExecutor);
      futures.add(validationDataFuture);
    }
    return futures;
  }

  private void extractValidatedSignatureErrors(List<Future<SignatureValidationData>> validationFutures) {
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

  public void setValidateManifest(boolean validateManifest) {
    this.validateManifest = validateManifest;
  }

  private void extractSignatureErrors(SignatureValidationData validationData) {
    logger.debug("Extracting signature errors for signature " + validationData.getSignatureId());
    signatureValidationData.add(validationData);
    SignatureValidationResult validationResult = validationData.getValidationResult();
    List<DigiDoc4JException> signatureErrors = validationResult.getErrors();
    errors.addAll(signatureErrors);
    warnings.addAll(validationResult.getWarnings());
  }

  private void extractManifestErrors(List<Signature> signatures) {
    logger.debug("Extracting manifest errors");
    manifestErrors = findManifestErrors(signatures);
    errors.addAll(manifestErrors);
  }

  private BDocValidationResult createValidationResult() {
    BDocValidationReportBuilder reportBuilder = new BDocValidationReportBuilder(signatureValidationData, manifestErrors);
    BDocValidationResult result = new BDocValidationResult();
    result.setErrors(errors);
    result.setWarnings(warnings);
    result.setContainerErrorsOnly(manifestErrors);
    result.setReportBuilder(reportBuilder);
    return result;
  }

  private List<DigiDoc4JException> findManifestErrors(List<Signature> signatures) {
    if (!validateManifest || containerParseResult == null) {
      return Collections.emptyList();
    }
    ManifestParser manifestParser = containerParseResult.getManifestParser();
    if (manifestParser == null || !manifestParser.containsManifestFile()) {
      logger.error("Container is missing manifest.xml");
      List<DigiDoc4JException> manifestExceptions = new ArrayList<>();
      manifestExceptions.add(new UnsupportedFormatException("Container does not contain a manifest file"));
      return manifestExceptions;
    }
    List<DigiDoc4JException> manifestExceptions = new ArrayList<>();
    List<DSSDocument> detachedContents = containerParseResult.getDetachedContents();
    List<String> manifestErrors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    for (String manifestError : manifestErrors) {
      manifestExceptions.add(new DigiDoc4JException(manifestError));
    }
    return manifestExceptions;
  }

}
