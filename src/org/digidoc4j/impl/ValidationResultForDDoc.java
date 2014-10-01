package org.digidoc4j.impl;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.ArrayList;
import java.util.List;

/**
 * Overview of errors and warnings for DDoc
 */
public class ValidationResultForDDoc implements ValidationResult {

  static final Logger logger = LoggerFactory.getLogger(ValidationResultForDDoc.class);

  private List<DigiDoc4JException> containerExceptions = new ArrayList<DigiDoc4JException>();
  private boolean hasFatalErrors = false;
  private List<DigiDoc4JException> errors = new ArrayList<DigiDoc4JException>();
  private List<DigiDoc4JException> warnings = new ArrayList<DigiDoc4JException>();

  private Document report;
  private Element rootElement;


  /**
   * Constructor
   *
   * @param documentFormat add description
   * @param exceptions     add description
   */
  public ValidationResultForDDoc(String documentFormat, List<DigiDocException> exceptions) {
    this(documentFormat, exceptions, null);
    logger.debug("");
  }


  /**
   * Constructor
   *
   * @param documentFormat          add description
   * @param exceptions              add description
   * @param openContainerExceptions list of exceptions encountered when opening the container
   */

  public ValidationResultForDDoc(String documentFormat, List<DigiDocException> exceptions,
                                 List<DigiDocException> openContainerExceptions) {
    Element childElement;

    initXMLReport();
    if (openContainerExceptions != null) {
      for (DigiDocException exception : openContainerExceptions) {
        DigiDoc4JException digiDoc4JException = new DigiDoc4JException(exception.getCode(), exception.getMessage());
        containerExceptions.add(digiDoc4JException);
        if (SignedDoc.hasFatalErrs((ArrayList) openContainerExceptions)) {
          hasFatalErrors = true;
        }
      }
      exceptions.addAll(0, openContainerExceptions);
    }


    for (DigiDocException exception : exceptions) {
      String message = exception.getMessage();
      int code = exception.getCode();
      DigiDoc4JException digiDoc4JException = new DigiDoc4JException(code, message);
      if (isWarning(documentFormat, digiDoc4JException)) {
        logger.debug("Validation warning." + " Code: " + code + ", message: " + message);
        warnings.add(digiDoc4JException);
        childElement = report.createElement("warning");
        childElement.setAttribute("Code", Integer.toString(code));
        childElement.setAttribute("Message", message);
      } else {
        logger.debug("Validation error." + " Code: " + code + ", message: " + message);
        errors.add(digiDoc4JException);
        childElement = report.createElement("error");
        childElement.setAttribute("Code", Integer.toString(code));
        childElement.setAttribute("Message", message);
      }
      rootElement.appendChild(childElement);
    }
  }

  /**
   * Does the container have fatal errors
   *
   * @return true if fatal errors have been encountered
   */
  public boolean hasFatalErrors() {
    return hasFatalErrors;
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

  private void initXMLReport() {

    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    try {
      DocumentBuilder db = dbf.newDocumentBuilder();
      report = db.newDocument();

      rootElement = report.createElement("root");
      report.appendChild(rootElement);

      Comment comment = report.createComment("DDoc verification result");
      report.insertBefore(comment, rootElement);

    } catch (ParserConfigurationException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public List<DigiDoc4JException> getErrors() {
    logger.debug("Returning " + errors.size() + " errors");
    return errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    logger.debug("Returning " + warnings.size() + " warnings");
    return warnings;
  }

  @Override
  public boolean hasErrors() {
    boolean hasErrors = (errors.size() != 0);
    logger.debug("Has Errors: " + hasErrors);
    return hasErrors;
  }

  @Override
  public boolean hasWarnings() {
    boolean hasWarnings = (warnings.size() != 0);
    logger.debug("Has warnings: " + hasWarnings);
    return hasWarnings;
  }

  @Override
  public boolean isValid() {
    return !hasErrors();
  }


  @Override
  public String getReport() {
    return reportToString(report);
  }

  static String reportToString(Document document) {
    DOMImplementationLS domImplementation = (DOMImplementationLS) document.getImplementation();
    LSSerializer lsSerializer = domImplementation.createLSSerializer();
    return lsSerializer.writeToString(document);
  }


  /**
   * Get list of exceptions encountered when opening the container
   *
   * @return List of exceptions
   */
  public List<DigiDoc4JException> getContainerErrors() {
    return containerExceptions;
  }
}
