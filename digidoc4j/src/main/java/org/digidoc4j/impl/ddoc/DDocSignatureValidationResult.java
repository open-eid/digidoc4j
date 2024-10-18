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

import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.AbstractContainerValidationResult;
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
import java.util.Iterator;
import java.util.List;

/**
 * Overview of errors and warnings for DDoc signature
 */
public class DDocSignatureValidationResult extends AbstractContainerValidationResult implements ContainerValidationResult {

  private final Logger log = LoggerFactory.getLogger(DDocSignatureValidationResult.class);
  private Document document;
  private Element rootElement;
  private boolean hasFatalErrors = false;

  /**
   * Constructor
   *
   * @param exceptions list of validation exceptions
   * @param documentFormat document format
   */
  public DDocSignatureValidationResult(List<DigiDocException> exceptions, String documentFormat) {
    this(exceptions, null, documentFormat);
  }

  /**
   * Constructor
   *
   * @param exceptions list of validation exceptions
   * @param openContainerExceptions list of exceptions encountered when opening the container
   * @param documentFormat document format
   *
   * @deprecated Deprecated for removal. Use {@link DDocContainerValidationResult} for encapsulating DDOC container
   * validation results.
   */
  @Deprecated
  public DDocSignatureValidationResult(List<DigiDocException> exceptions,
                                       List<DigiDocException> openContainerExceptions,
                                       String documentFormat) {
    this.initXMLReport();
    if (openContainerExceptions != null) {
      removeDuplicates(exceptions);
      removeDuplicates(openContainerExceptions);
      for (DigiDocException exception : openContainerExceptions) {
        super.containerErrors.add(new DigiDoc4JException(exception.getCode(), exception.getMessage()));
        if (SignedDoc.hasFatalErrs((ArrayList) openContainerExceptions)) {
          this.hasFatalErrors = true;
        }
      }
      for (DigiDocException digiDocException: exceptions) {
        for(Iterator<DigiDocException> iterator = openContainerExceptions.iterator(); iterator.hasNext();) {
          DigiDocException openContainerException = iterator.next();
          if(digiDocException.getMessage().equals(openContainerException.getMessage())) {
              iterator.remove();
          }
        }
      }
      exceptions.addAll(0, openContainerExceptions);
    }
    for (DigiDocException exception : exceptions) {
      if (isWarning(exception, documentFormat)) {
        this.generateReport(exception, false);
      } else {
        this.generateReport(exception, true);
      }
    }
    this.report = this.toReportString(this.document);
  }

  @Override
  public List<String> getSignatureIdList() {
    throw new NotSupportedException("Not supported for " + getResultName() + " validation result");
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected String getResultName() {
    return "DDoc signature";
  }

  private void removeDuplicates(List<DigiDocException> exceptions) {
      for (int i = 0; i < exceptions.size(); i++) {
          for (int j = i + 1; j < exceptions.size(); j++) {
              boolean isErrorCodesEqual = exceptions.get(i).getCode() == exceptions.get(j).getCode();
              boolean isErrorMessagesEqual = exceptions.get(i).getMessage().equals(exceptions.get(j).getMessage());
              if (isErrorCodesEqual && isErrorMessagesEqual) {
                  exceptions.remove(j);
                  j--;
              }
          }
      }
  }

  private boolean isWarning(DigiDocException e, String documentFormat) {
      return (e.getCode() == DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH
              || e.getCode() == DigiDocException.ERR_OLD_VER
              || e.getCode() == DigiDocException.ERR_TEST_SIGNATURE
              || e.getCode() == DigiDocException.WARN_WEAK_DIGEST
              || (e.getCode() == DigiDocException.ERR_ISSUER_XMLNS && !documentFormat.equals(SignedDoc.FORMAT_SK_XML)));
  }

  private void generateReport(DigiDocException exception, boolean isError) {
    Element childElement;
    String warningOrError;
    String message = exception.getMessage();
    int code = exception.getCode();
    if (!isError) {
      warningOrError = "warning";
      this.warnings.add(new DigiDoc4JException(code, message));
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

  /**
   * Does the container have fatal errors
   *
   * @return true if fatal errors have been encountered
   */
  public boolean hasFatalErrors() {
    return hasFatalErrors;
  }

}
