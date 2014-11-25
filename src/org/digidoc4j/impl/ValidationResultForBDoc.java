package org.digidoc4j.impl;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.ArrayList;
import java.util.List;

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
   * @param report         creates validation result from report
   * @param manifestErrors was there any issues with manifest file
   */
  public ValidationResultForBDoc(Reports report, List<String> manifestErrors) {
    logger.debug("");

    initializeReportDOM();

    for (String manifestError : manifestErrors) {
      manifestValidationExceptions.add(new DigiDoc4JException(manifestError));
    }
    if (manifestValidationExceptions.size() != 0) errors.addAll(manifestValidationExceptions);

    do {
      SimpleReport simpleReport = report.getSimpleReport();

      String signatureId = simpleReport.getSignatureIds().get(0);

      List<Conclusion.BasicInfo> results = simpleReport.getErrors(signatureId);
      for (Conclusion.BasicInfo result : results) {
        String message = result.toString();
        logger.debug("Validation error: " + message);
        errors.add(new DigiDoc4JException(message));
      }
      results = simpleReport.getWarnings(signatureId);
      for (Conclusion.BasicInfo result : results) {
        String message = result.toString();
        logger.debug("Validation warning: " + message);
        warnings.add(new DigiDoc4JException(message));
      }

      createXMLReport(simpleReport);
      if (logger.isDebugEnabled()) {
        logger.debug(simpleReport.toString());
      }
      report = report.getNextReports();

    } while (report != null);

    addErrorsToXMLReport(manifestErrors);
  }

  private void addErrorsToXMLReport(List<String> manifestErrors) {
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
    try {
      DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
      DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
      reportDocument = docBuilder.newDocument();
      reportDocument.appendChild(reportDocument.createElement("ValidationReport"));
    } catch (ParserConfigurationException e) {
      e.printStackTrace();
    }

  }

  private void createXMLReport(SimpleReport simpleReport) {

    Element signatureValidation = reportDocument.createElement("SignatureValidation");
    signatureValidation.setAttribute("ID", simpleReport.getSignatureIds().get(0));
    reportDocument.getDocumentElement().appendChild(signatureValidation);

    Element rootElement = simpleReport.getRootElement();
    NodeList childNodes = rootElement.getChildNodes();
    for (int i = 0; i < childNodes.getLength(); i++) {
      Node node = childNodes.item(i);
      removeNamespace(node);
      Node importNode = reportDocument.importNode(node, true);

      signatureValidation.appendChild(importNode);
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
    return errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    return warnings;
  }

  @Override
  public boolean hasErrors() {
    return (errors.size() != 0);
  }

  @Override
  public boolean hasWarnings() {
    return (warnings.size() != 0);
  }

  @Override
  public boolean isValid() {
    return !hasErrors();
  }

  @Override
  public String getReport() {
    return new String(DSSXMLUtils.transformDomToByteArray(reportDocument));
  }

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return manifestValidationExceptions;
  }
}
