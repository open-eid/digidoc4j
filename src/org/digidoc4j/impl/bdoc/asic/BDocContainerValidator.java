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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.digidoc4j.Signature;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.digidoc4j.impl.bdoc.BDocValidationReportBuilder;
import org.digidoc4j.impl.bdoc.BDocValidationResult;
import org.digidoc4j.impl.bdoc.manifest.ManifestParser;
import org.digidoc4j.impl.bdoc.manifest.ManifestValidator;
import org.digidoc4j.impl.bdoc.xades.validation.XadesValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.validation.reports.Reports;

public class BDocContainerValidator implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(BDocContainerValidator.class);
  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();
  private AsicParseResult containerParseResult;
  private boolean validateManifest;
  private transient Map<String, List<DigiDoc4JException>> signatureVerificationErrors;
  private transient List<Reports> validationReports;
  private transient List<DigiDoc4JException> manifestErrors;
  private transient BDocValidationReportBuilder reportBuilder;

  public BDocContainerValidator() {
    validateManifest = false;
  }

  public BDocContainerValidator(AsicParseResult containerParseResult) {
    this.containerParseResult = containerParseResult;
    validateManifest = true;
  }

  public ValidationResult validate(List<Signature> signatures) {
    logger.debug("Validating container");
    signatureVerificationErrors = new HashMap<>();
    validationReports = new ArrayList<>();
    for (Signature signature : signatures) {
      extractSignatureErrors(signature);
    }
    extractManifestErrors(signatures);
    reportBuilder = new BDocValidationReportBuilder(validationReports, manifestErrors, signatureVerificationErrors);

    BDocValidationResult result = createValidationResult();
    logger.info("Is container valid: " + result.isValid());
    return result;
  }

  public void setValidateManifest(boolean validateManifest) {
    this.validateManifest = validateManifest;
  }

  private void extractSignatureErrors(Signature signature) {
    SignatureValidationResult validationResult = signature.validateSignature();
    List<DigiDoc4JException> signatureErrors = validationResult.getErrors();
    errors.addAll(signatureErrors);
    warnings.addAll(validationResult.getWarnings());
    signatureVerificationErrors.put(signature.getId(), signatureErrors);
    XadesValidationResult validationReport = ((BDocSignature) signature).getDssValidationReport();
    Reports dssValidationReport = validationReport.getReport();
    validationReports.add(dssValidationReport);
  }

  private void extractManifestErrors(List<Signature> signatures) {
    manifestErrors = findManifestErrors(signatures);
    errors.addAll(manifestErrors);
  }

  private BDocValidationResult createValidationResult() {
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
