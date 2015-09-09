/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.ddoc.ValidationResultForDDoc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Overview of errors and warnings for BDoc
 */

public class ValidationResultForBDoc implements ValidationResult {
  static final Logger logger = LoggerFactory.getLogger(ValidationResultForDDoc.class);
  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();
  private List<DigiDoc4JException> manifestValidationExceptions = new ArrayList<>();
  private Document reportDocument;

  /**
   * Constructor
   *
   * @param report                       creates validation result from report
   * @param signatures                   list of signatures
   * @param manifestErrors               manifest verification errors
   * @param additionalVerificationErrors digidoc4J additional verification errors
   */
  public ValidationResultForBDoc(Reports report, Collection<Signature> signatures, List<String> manifestErrors,
                                 Map<String, List<DigiDoc4JException>> additionalVerificationErrors) {
    logger.debug("");

    initializeReportDOM();

    for (String manifestError : manifestErrors) {
      manifestValidationExceptions.add(new DigiDoc4JException(manifestError));
    }
    if (manifestValidationExceptions.size() != 0) errors.addAll(manifestValidationExceptions);

    for (Signature signature : signatures) {
      List<DigiDoc4JException> signatureValidationResult = signature.validate();

      if (signatureValidationResult.size() != 0) {
        errors.addAll(signatureValidationResult);
      }
    }

    do {
      SimpleReport simpleReport = report.getSimpleReport();

      //check with several signatures as well in one signature file (in estonia we are not producing such signatures)
      String signatureId = simpleReport.getSignatureIdList().get(0);

      List<Conclusion.BasicInfo> results = simpleReport.getWarnings(signatureId);
      for (Conclusion.BasicInfo result : results) {
        String message = result.toString();
        logger.debug("Validation warning: " + message);
        warnings.add(new DigiDoc4JException(message));
      }

      createXMLReport(simpleReport, additionalVerificationErrors.get(signatureId));
      if (logger.isDebugEnabled()) {
        logger.debug(simpleReport.toString());
      }
      report = report.getNextReports();

    } while (report != null);

    addErrorsToXMLReport(manifestErrors);
  }

  private void addErrorsToXMLReport(List<String> manifestErrors) {
    logger.debug("");
    Element manifestValidation = reportDocument.createElement("ManifestValidation");
    reportDocument.getDocumentElement().appendChild(manifestValidation);
    for (int i = 0; i < manifestErrors.size(); i++) {
      Attr attribute = reportDocument.createAttribute("Error");
      attribute.setValue(Integer.toString(i));
      manifestValidation.setAttributeNode(attribute);

      Element errorDescription = reportDocument.createElement("Description");
      errorDescription.appendChild(reportDocument.createTextNode(manifestErrors.get(i)));
      manifestValidation.appendChild(errorDescription);
    }
  }

  private void initializeReportDOM() {
    logger.debug("");
    try {
      DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
      DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
      reportDocument = docBuilder.newDocument();
      reportDocument.appendChild(reportDocument.createElement("ValidationReport"));
    } catch (ParserConfigurationException e) {
      e.printStackTrace();
    }

  }

  private void createXMLReport(SimpleReport simpleReport, List<DigiDoc4JException> additionalErrors) {
    logger.debug("");
    Element signatureValidation = reportDocument.createElement("SignatureValidation");
    signatureValidation.setAttribute("ID", simpleReport.getSignatureIdList().get(0));
    reportDocument.getDocumentElement().appendChild(signatureValidation);

    Element rootElement = simpleReport.getRootElement();
    NodeList childNodes = rootElement.getChildNodes();
    for (int i = 0; i < childNodes.getLength(); i++) {
      Node node = childNodes.item(i);
      removeNamespace(node);
      Node importNode = reportDocument.importNode(node, true);
      signatureValidation.appendChild(importNode);
    }
    addAdditionalErrors(additionalErrors, signatureValidation);
  }

  private void addAdditionalErrors(List<DigiDoc4JException> additionalErrors, Element signatureValidation) {
    logger.debug("");
    if (additionalErrors != null) {
      Element additionalValidation = reportDocument.createElement("AdditionalValidation");
      signatureValidation.getElementsByTagName("Signature").item(0).appendChild(additionalValidation);
      if (additionalErrors.size() > 0)
        signatureValidation.getElementsByTagName("ValidSignaturesCount").item(0).setTextContent("0");

      for (int i = 0; i < additionalErrors.size(); i++) {
        Attr attribute = reportDocument.createAttribute("Error");
        attribute.setValue(Integer.toString(i));
        additionalValidation.setAttributeNode(attribute);
        Element errorDescription = reportDocument.createElement("Description");
        //noinspection ThrowableResultOfMethodCallIgnored
        errorDescription.appendChild(reportDocument.createTextNode(additionalErrors.get(i).getMessage()));
        additionalValidation.appendChild(errorDescription);
      }
    }
  }

  private static void removeNamespace(Node node) {
    Document document = node.getOwnerDocument();
    if (node.getNodeType() == Node.ELEMENT_NODE) {
      document.renameNode(node, null, node.getNodeName());
    }
    NodeList list = node.getChildNodes();
    for (int i = 0; i < list.getLength(); ++i) {
      removeNamespace(list.item(i));
    }
  }

  @Override
  public List<DigiDoc4JException> getErrors() {
    logger.debug("");
    return errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    logger.debug("");
    return warnings;
  }

  @Override
  public boolean hasErrors() {
    logger.debug("");
    return (errors.size() != 0);
  }

  @Override
  public boolean hasWarnings() {
    logger.debug("");
    return (warnings.size() != 0);
  }

  @Override
  public boolean isValid() {
    logger.debug("");
    return !hasErrors();
  }

  @Override
  public String getReport() {
    logger.debug("");
    return new String(DSSXMLUtils.transformDomToByteArray(reportDocument));
  }

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    logger.debug("");
    return manifestValidationExceptions;
  }
}
