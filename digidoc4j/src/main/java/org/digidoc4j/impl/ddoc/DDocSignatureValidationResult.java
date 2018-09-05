/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.AbstractSignatureValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;

/**
 * Overview of errors and warnings for DDoc
 */
public class DDocSignatureValidationResult extends AbstractSignatureValidationResult implements
    ContainerValidationResult {

  private final Logger log = LoggerFactory.getLogger(DDocSignatureValidationResult.class);
  private List<DigiDoc4JException> containerExceptions = new ArrayList<>();
  private Document document;
  private Element rootElement;
  private boolean hasFatalErrors = false;

  /**
   * Constructor
   *
   * @param exceptions add description
   */
  public DDocSignatureValidationResult(List<DigiDocException> exceptions) {
    this(exceptions, null);
  }

  /**
   * Constructor
   *
   * @param exceptions              add description
   * @param openContainerExceptions list of exceptions encountered when opening the container
   */

  public DDocSignatureValidationResult(List<DigiDocException> exceptions,
                                       List<DigiDocException> openContainerExceptions) {
    this.initXMLReport();
    if (openContainerExceptions != null) {
      for (DigiDocException exception : openContainerExceptions) {
        this.containerExceptions.add(new DigiDoc4JException(exception.getCode(), exception.getMessage()));
        if (SignedDoc.hasFatalErrs((ArrayList) openContainerExceptions)) {
          this.hasFatalErrors = true;
        }
      }
      exceptions.addAll(0, openContainerExceptions);
    }
    for (DigiDocException exception : exceptions) {
      if (exception.getMessage().contains("X509IssuerName has none or invalid namespace:")
          || exception.getMessage().contains("X509SerialNumber has none or invalid namespace:")) {
        this.generateReport(exception, false);
      } else {
        this.generateReport(exception, true);
      }
    }
    this.report = this.toReportString(this.document);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected String getResultName() {
    return "DDoc container";
  }

  private void generateReport(DigiDocException exception, boolean isError) {
    Element childElement;
    String warningOrError;
    String message = exception.getMessage();
    int code = exception.getCode();
    if (!isError) {
      warningOrError = "warning";
    } else {
      this.errors.add(new DigiDoc4JException(code, message));
      warningOrError = "error";
    }
    this.log.debug("Validation " + warningOrError + "." + " Code: " + code + ", message: " + message);
    childElement = this.document.createElement(warningOrError);
    childElement.setAttribute("Code", Integer.toString(code));
    childElement.setAttribute("Message", message);
    this.rootElement.appendChild(childElement);
  }

  private void initXMLReport() {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    try {
      DocumentBuilder db = dbf.newDocumentBuilder();
      this.document = db.newDocument();
      this.rootElement = this.document.createElement("root");
      this.document.appendChild(this.rootElement);
      Comment comment = this.document.createComment("DDoc verification result");
      this.document.insertBefore(comment, this.rootElement);
    } catch (ParserConfigurationException e) {
      throw new DigiDoc4JException(e);
    }
  }

  private String toReportString(Document document) {
    DOMImplementationLS documentImplementation = (DOMImplementationLS) document.getImplementation();
    LSSerializer lsSerializer = documentImplementation.createLSSerializer();
    return lsSerializer.writeToString(document);
  }

  /*
   * ACCESSORS
   */

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return containerExceptions;
  }

  /**
   * Does the container have fatal errors
   *
   * @return true if fatal errors have been encountered
   */
  public boolean hasFatalErrors() {
    return hasFatalErrors;
  }

}
