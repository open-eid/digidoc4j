/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.simplereport.jaxb.XmlValidationPolicy;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.report.ContainerValidationReport;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.digidoc4j.impl.asic.report.SignatureValidationReportCreator;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.File;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ASIC validation report builder
 */
public class AsicValidationReportBuilder {

  private static final Logger logger = LoggerFactory.getLogger(AsicValidationReportBuilder.class);
  private List<DigiDoc4JException> manifestErrors;
  private List<SignatureValidationData> signatureValidationData;
  private String reportInXml;

  /**
   * @param signatureValidationData list of signature validation data
   * @param manifestErrors          list of manifest errors
   */
  public AsicValidationReportBuilder(List<SignatureValidationData> signatureValidationData,
                                     List<DigiDoc4JException> manifestErrors) {
    logger.debug("Initializing ASiC validation report builder");
    this.manifestErrors = manifestErrors;
    this.signatureValidationData = signatureValidationData;
  }

  public String buildXmlReport() {
    if (reportInXml == null) {
      reportInXml = generateNewReport();
    }
    return reportInXml;
  }

  /**
   * Gets signature Validation Reports.
   *
   * @return List<SignatureValidationReport>
   */
  public List<SignatureValidationReport> buildSignatureValidationReports() {
    return createSignaturesValidationReport();
  }

  /**
   * Gets signature Simple Reports.
   *
   * @return List<SimpleReport>
   */
  public List<eu.europa.esig.dss.simplereport.SimpleReport> buildSignatureSimpleReports() {
    List<eu.europa.esig.dss.simplereport.SimpleReport> signaturesReport = new ArrayList<>();
    for (SignatureValidationData validationData : signatureValidationData) {
      signaturesReport.add(validationData.getReport().getReports().getSimpleReport());
    }
    return signaturesReport;
  }

  public Map<String, String> buildSignatureIdMap() {
    return signatureValidationData.stream().collect(Collectors.toMap(
            SignatureValidationData::getSignatureId,
            SignatureValidationData::getSignatureUniqueId,
            (v1, v2) -> v1
    ));
  }

  /**
   * Save DSS validation reports in given directory.
   *
   * @param directory Directory where to save XML files.
   */
  public void saveXmlReports(Path directory) {
    try {
      byte[] bytes = this.buildXmlReport().getBytes("UTF-8");
      DSSUtils.saveToFile(bytes, new File(directory + File.separator + "validationReport.xml"));
      logger.info("Validation report is generated");
    } catch (UnsupportedEncodingException e) {
      logger.error(e.getMessage());
    }
    if (!signatureValidationData.isEmpty()) {
      int n = signatureValidationData.size();
      for (int i = 0; i < n; i++) {
        SignatureValidationData validationData = signatureValidationData.get(i);
        Reports reports = validationData.getReport().getReports();
        try {
          byte[] bytes = reports.getXmlDiagnosticData().getBytes("UTF-8");
          DSSUtils.saveToFile(bytes,
                  new File(directory + File.separator + "validationDiagnosticData" + Integer.toString(i) + ".xml"));
          logger.info("Validation diagnostic data report is generated");
        } catch (UnsupportedEncodingException e) {
          logger.error(e.getMessage());
        }

        try {
          byte[] bytes = reports.getXmlSimpleReport().getBytes("UTF-8");
          DSSUtils.saveToFile(bytes, new File(directory + File.separator + "validationSimpleReport" + Integer.toString(i) + ".xml"));
          logger.info("Validation simple report is generated");
        } catch (UnsupportedEncodingException e) {
          logger.error(e.getMessage());
        }

        try {
          byte[] bytes = reports.getXmlDetailedReport().getBytes("UTF-8");
          DSSUtils.saveToFile(bytes, new File(directory + File.separator + "validationDetailReport" + Integer.toString(i) + ".xml"));
          logger.info("Validation detailed report is generated");
        } catch (UnsupportedEncodingException e) {
          logger.error(e.getMessage());
        }
      }
    }
  }

  private String generateNewReport() {
    logger.debug("Generating a new XML validation report");
    ContainerValidationReport report = new ContainerValidationReport();
    report.setValidationPolicy(extractValidationPolicy());
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

  private XmlValidationPolicy extractValidationPolicy() {
    if (signatureValidationData.isEmpty()) {
      return null;
    }
    SignatureValidationData validationData = signatureValidationData.get(0);
    XmlSimpleReport simpleReport = validationData.getReport().getReports().getSimpleReportJaxb();
    return simpleReport.getValidationPolicy();
  }

  private int extractValidSignaturesCount() {
    int validSignaturesCount = 0;
    for (SignatureValidationData validationData : signatureValidationData) {
      ValidationResult validationResult = validationData.getValidationResult();
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
