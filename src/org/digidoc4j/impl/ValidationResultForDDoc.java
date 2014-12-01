/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

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

  private Document report;
  private Element rootElement;


  /**
   * Constructor
   *
   * @param exceptions     add description
   */
  public ValidationResultForDDoc(List<DigiDocException> exceptions) {
    this(exceptions, null);
    logger.debug("");
  }

  /**
   * Constructor
   *
   * @param exceptions              add description
   * @param openContainerExceptions list of exceptions encountered when opening the container
   */

  public ValidationResultForDDoc(List<DigiDocException> exceptions,
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
      logger.debug("Validation error." + " Code: " + code + ", message: " + message);
      errors.add(digiDoc4JException);
      childElement = report.createElement("error");
      childElement.setAttribute("Code", Integer.toString(code));
      childElement.setAttribute("Message", message);
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
    logger.debug("");
    return new ArrayList<DigiDoc4JException>();
  }

  @Override
  public boolean hasErrors() {
    boolean hasErrors = (errors.size() != 0);
    logger.debug("Has Errors: " + hasErrors);
    return hasErrors;
  }

  @Override
  public boolean hasWarnings() {
    logger.debug("");
    return false;
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

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return containerExceptions;
  }
}
