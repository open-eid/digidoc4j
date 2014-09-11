package org.digidoc4j;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import org.digidoc4j.api.ValidationResult;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps errors and warnings into a ValidationResult object
 */
public class ValidationResultMapper {
  private static final Logger logger = LoggerFactory.getLogger(ValidationResultMapper.class);

  protected ValidationResultMapper() {
    logger.debug("");
  }

  static ValidationResult fromValidator(SignedDocumentValidator validator) {
    logger.debug("");
    List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();
    List<DigiDoc4JException> validationWarnings = new ArrayList<DigiDoc4JException>();

    SimpleReport simpleReport = validator.getSimpleReport();

    List<String> signatureIds = simpleReport.getSignatureIds();

    for (String signatureId : signatureIds) {
      List<Conclusion.BasicInfo> results = simpleReport.getErrors(signatureId);
      for (Conclusion.BasicInfo result : results) {
        String message = result.toString();
        logger.debug("Validation error: " + message);
        validationErrors.add(new DigiDoc4JException(message));
      }
      results = simpleReport.getWarnings(signatureId);
      for (Conclusion.BasicInfo result : results) {
        String message = result.toString();
        logger.debug("Validation warning: " + message);
        validationWarnings.add(new DigiDoc4JException(message));
      }
    }

    logger.debug(simpleReport.toString());

    return new ValidationResult(validationErrors, validationWarnings);
  }

  static ValidationResult fromList(String documentFormat, List<DigiDocException> exceptions) {
    logger.debug("");
    List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();
    List<DigiDoc4JException> validationWarnings = new ArrayList<DigiDoc4JException>();


    for (DigiDocException exception : exceptions) {
      String message = exception.getMessage();
      int code = exception.getCode();
      DigiDoc4JException digiDoc4JException = new DigiDoc4JException(code, message);
      if (isWarning(documentFormat, digiDoc4JException)) {
        logger.debug("Validation warning. Code: " + code + ", message: " + message);
        validationWarnings.add(digiDoc4JException);
      } else {
        logger.debug("Validation error. Code: " + code + ", message: " + message);
        validationErrors.add(digiDoc4JException);
      }
    }
    return new ValidationResult(validationErrors, validationWarnings);
  }

  static boolean isWarning(String documentFormat, DigiDoc4JException exception) {
    logger.debug("");
    int errorCode = exception.getErrorCode();
    return (errorCode == DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH
        || errorCode == DigiDocException.ERR_OLD_VER
        || errorCode == DigiDocException.ERR_TEST_SIGNATURE
        || errorCode == DigiDocException.WARN_WEAK_DIGEST
        || (errorCode == DigiDocException.ERR_ISSUER_XMLNS && !documentFormat.equals(SignedDoc.FORMAT_SK_XML)));
  }
}
