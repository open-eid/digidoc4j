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

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.report.ContainerValidationReport;
import org.digidoc4j.impl.bdoc.report.SignatureValidationReport;
import org.digidoc4j.impl.bdoc.report.SignatureValidationReportCreator;
import org.digidoc4j.impl.bdoc.xades.validation.SignatureValidationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.jaxb.simplereport.XmlPolicy;

public class BDocValidationReportBuilder {

  private final static Logger logger = LoggerFactory.getLogger(BDocValidationReportBuilder.class);
  private List<DigiDoc4JException> manifestErrors;
  private List<SignatureValidationData> signatureValidationData;
  private String reportInXml;

  public BDocValidationReportBuilder(List<SignatureValidationData> signatureValidationData, List<DigiDoc4JException> manifestErrors) {
    logger.debug("Initializing BDoc validation report builder");
    this.manifestErrors = manifestErrors;
    this.signatureValidationData = signatureValidationData;
  }

  public String buildXmlReport() {
    if (reportInXml == null) {
      reportInXml = generateNewReport();
    }
    return reportInXml;
  }

  private String generateNewReport() {
    logger.debug("Generating a new XML validation report");
    ContainerValidationReport report = new ContainerValidationReport();
    report.setPolicy(extractValidationPolicy());
    report.setValidationTime(new Date());
    report.setSignaturesCount(signatureValidationData.size());
    report.setValidSignaturesCount(extractValidSignaturesCount());
    report.setSignatures(createSignaturesValidationReport());
    report.setContainerErrors(createContainerErrors());
    return createFormattedXmlString(report);
  }

  private List<SignatureValidationReport> createSignaturesValidationReport() {
    List<SignatureValidationReport> signaturesReport = new ArrayList<>();
    for (SignatureValidationData validationData : signatureValidationData) {
      SignatureValidationReport signatureValidationReport = SignatureValidationReportCreator.create(validationData);
      signaturesReport.add(signatureValidationReport);
    }
    return signaturesReport;
  }

  private XmlPolicy extractValidationPolicy() {
    if (signatureValidationData.isEmpty()) {
      return null;
    }
    SignatureValidationData validationData = signatureValidationData.get(0);
    SimpleReport simpleReport = validationData.getReport().getReport().getSimpleReportJaxb();
    return simpleReport.getPolicy();
  }

  private int extractValidSignaturesCount() {
    int validSignaturesCount = 0;
    for (SignatureValidationData validationData : signatureValidationData) {
      SignatureValidationResult validationResult = validationData.getValidationResult();
      if (validationResult.isValid()) {
        validSignaturesCount++;
      }
    }
    return validSignaturesCount;
  }

  private List<String> createContainerErrors() {
    List<String> containerErrors = new ArrayList<>();
    for (DigiDoc4JException manifestError : manifestErrors) {
      containerErrors.add(manifestError.getMessage());
    }
    return containerErrors;
  }

  private String createFormattedXmlString(ContainerValidationReport simpleReport) {
    try {
      JAXBContext context = JAXBContext.newInstance(ContainerValidationReport.class);
      Marshaller marshaller = context.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
      StringWriter stringWriter = new StringWriter();
      marshaller.marshal(simpleReport, stringWriter);
      String xmlReport = stringWriter.toString();
      logger.trace(xmlReport);
      return xmlReport;
    } catch (JAXBException e) {
      throw new TechnicalException("Failed to create validation report in XML: " + e.getMessage(), e);
    }
  }
}
