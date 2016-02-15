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

import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;

public class BDocValidationReportBuilder {

  private final static Logger logger = LoggerFactory.getLogger(BDocValidationReportBuilder.class);
  private Document reportDocument;
  private List<Reports> validationReports;
  private List<DigiDoc4JException> manifestErrors;
  private Map<String, List<DigiDoc4JException>> signatureVerificationErrors;
  private String reportInXml;

  public BDocValidationReportBuilder(List<Reports> validationReports, List<DigiDoc4JException> manifestErrors, Map<String, List<DigiDoc4JException>> signatureVerificationErrors) {
    logger.debug("Initializing BDoc validation report builder");
    this.validationReports = validationReports;
    this.manifestErrors = manifestErrors;
    this.signatureVerificationErrors = signatureVerificationErrors;
  }

  public String buildXmlReport() {
    if(reportInXml == null) {
      reportInXml = generateNewReport();
    }
    return reportInXml;
  }

  private String generateNewReport() {
    logger.debug("Generating BDoc validation report in XML");
    initializeReportDOM();
    addErrorsInEveryReport();
    addManifestErrorsToXmlReport();
    return getReportAsXmlString();
  }

  private void addErrorsInEveryReport() {
    for(Reports report: validationReports) {
      addErrorsForEachReport(report);
    }
  }

  private void addErrorsForEachReport(Reports report) {
    do {
      SimpleReport simpleReport = report.getSimpleReport();
      //check with several signatures as well in one signature file (in estonia we are not producing such signatures)
      String signatureId = simpleReport.getSignatureIdList().get(0);
      createXMLReport(simpleReport, signatureVerificationErrors.get(signatureId));
      report = report.getNextReports();
    } while (report != null);
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

  private void addManifestErrorsToXmlReport() {
    Element manifestValidation = reportDocument.createElement("ManifestValidation");
    reportDocument.getDocumentElement().appendChild(manifestValidation);
    for (int i = 0; i < manifestErrors.size(); i++) {
      Attr attribute = reportDocument.createAttribute("Error");
      attribute.setValue(Integer.toString(i));
      manifestValidation.setAttributeNode(attribute);

      Element errorDescription = reportDocument.createElement("Description");
      DigiDoc4JException manifestError = manifestErrors.get(i);
      errorDescription.appendChild(reportDocument.createTextNode(manifestError.getMessage()));
      manifestValidation.appendChild(errorDescription);
    }
  }

  private void createXMLReport(SimpleReport simpleReport, List<DigiDoc4JException> additionalErrors) {
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

  private String getReportAsXmlString() {
    byte[] reportBytes = DSSXMLUtils.transformDomToByteArray(reportDocument);
    return new String(reportBytes);
  }

}
