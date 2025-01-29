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

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlValidationPolicy;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.cades.TimestampValidationData;
import org.digidoc4j.impl.asic.report.ContainerValidationReport;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.digidoc4j.impl.asic.report.SignatureValidationReportCreator;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;
import org.digidoc4j.impl.asic.report.TimestampValidationReportCreator;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidationData;
import org.digidoc4j.impl.asic.xades.validation.XadesValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * ASIC validation report builder
 */
public class AsicValidationReportBuilder {

  private static final Logger logger = LoggerFactory.getLogger(AsicValidationReportBuilder.class);

  private final List<DigiDoc4JException> containerErrors;
  private final List<DigiDoc4JException> containerWarnings;
  private final List<SignatureValidationData> signatureValidationData;
  private final List<TimestampValidationData> timestampValidationData;

  private String reportInXml;

  /**
   * @param signatureValidationData list of signature validation data
   * @param manifestErrors          list of manifest errors
   *
   * @deprecated Deprecated for removal. Use {@link #AsicValidationReportBuilder(List, List, List, List)} instead.
   */
  @Deprecated
  public AsicValidationReportBuilder(
          List<SignatureValidationData> signatureValidationData,
          List<DigiDoc4JException> manifestErrors
  ) {
    this(signatureValidationData, new ArrayList<>(), manifestErrors, new ArrayList<>());
  }

  public AsicValidationReportBuilder(
          List<SignatureValidationData> signatureValidationData,
          List<TimestampValidationData> timestampValidationData,
          List<DigiDoc4JException> containerErrors,
          List<DigiDoc4JException> containerWarnings
  ) {
    logger.debug("Initializing ASiC validation report builder");
    this.signatureValidationData = Objects.requireNonNull(signatureValidationData);
    this.timestampValidationData = Objects.requireNonNull(timestampValidationData);
    this.containerErrors = Objects.requireNonNull(containerErrors);
    this.containerWarnings = Objects.requireNonNull(containerWarnings);
  }

  public String buildXmlReport() {
    if (reportInXml == null) {
      reportInXml = generateNewXmlReport();
    }
    return reportInXml;
  }

  /**
   * Gets signature Validation Reports.
   *
   * @return List<SignatureValidationReport>
   */
  public List<SignatureValidationReport> buildSignatureValidationReports() {
    return createSignatureValidationReports();
  }

  /**
   * Gets timestamp token Validation Reports.
   *
   * @return List<TimestampValidationReport>
   */
  public List<TimestampValidationReport> buildTimestampValidationReports() {
    return createTimestampValidationReports();
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

  /**
   * Gets timestamp token Simple Reports.
   * Timestamp tokens may be covered by a single report and thus the list of reports might not correspond to the list
   * of all timestamp tokens in the container.
   *
   * @return List<SimpleReport>
   */
  public List<eu.europa.esig.dss.simplereport.SimpleReport> buildTimestampSimpleReports() {
    return timestampValidationData.stream()
            .map(TimestampValidationData::getEncapsulatingReports)
            .distinct()
            .map(Reports::getSimpleReport)
            .collect(Collectors.toCollection(ArrayList::new));
  }

  public List<eu.europa.esig.dss.simplereport.SimpleReport> buildAllSimpleReports() {
    List<eu.europa.esig.dss.simplereport.SimpleReport> reports = new ArrayList<>();
    if (CollectionUtils.isNotEmpty(signatureValidationData)) {
      reports.addAll(buildSignatureSimpleReports());
    }
    if (CollectionUtils.isNotEmpty(timestampValidationData)) {
      reports.addAll(buildTimestampSimpleReports());
    }
    return reports;
  }

  public Map<String, ValidationResult> buildSignatureValidationResultMap() {
    Map<String, ValidationResult> validationResultMap = new LinkedHashMap<>();
    for (SignatureValidationData validationData : signatureValidationData) {
      String key = validationData.getSignatureUniqueId();
      if (validationResultMap.containsKey(key)) {
        logger.warn("Signature unique ID collision detected, mapping '{}' to first matching result!", key);
      } else {
        validationResultMap.put(key, validationData.getValidationResult());
      }
    }
    return validationResultMap;
  }

  public Map<String, ValidationResult> buildTimestampValidationResultMap() {
    Map<String, ValidationResult> validationResultMap = new LinkedHashMap<>();
    for (TimestampValidationData validationData : timestampValidationData) {
      String key = validationData.getTimestampUniqueId();
      if (validationResultMap.containsKey(key)) {
        logger.warn("Timestamp unique ID collision detected, mapping '{}' to first matching result!", key);
      } else {
        validationResultMap.put(key, validationData.getValidationResult());
      }
    }
    return validationResultMap;
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
    DSSUtils.saveToFile(
            buildXmlReport().getBytes(StandardCharsets.UTF_8),
            directory.resolve("validationReport.xml").toFile()
    );
    logger.info("Validation report is generated");

    AtomicInteger indexCounter = new AtomicInteger(0);
    Stream.concat(
            signatureValidationData.stream()
                    .map(SignatureValidationData::getReport)
                    .map(XadesValidationResult::getReports),
            timestampValidationData.stream()
                    .map(TimestampValidationData::getEncapsulatingReports)
                    .distinct() // The results of multiple timestamp tokens can be contained in a single set of reports
                    //  and thus multiple timestamp validation data instances might reference the same set of reports.
    ).forEach(reports -> {
      int index = indexCounter.getAndIncrement();

      DSSUtils.saveToFile(
              reports.getXmlDiagnosticData().getBytes(StandardCharsets.UTF_8),
              directory.resolve("validationDiagnosticData" + index + ".xml").toFile()
      );
      logger.info("Validation diagnostic data report is generated");

      DSSUtils.saveToFile(
              reports.getXmlSimpleReport().getBytes(StandardCharsets.UTF_8),
              directory.resolve("validationSimpleReport" + index + ".xml").toFile()
      );
      logger.info("Validation simple report is generated");

      DSSUtils.saveToFile(
              reports.getXmlDetailedReport().getBytes(StandardCharsets.UTF_8),
              directory.resolve("validationDetailReport" + index + ".xml").toFile()
      );
      logger.info("Validation detailed report is generated");
    });
  }

  ContainerValidationReport generateNewValidationReport() {
    ContainerValidationReport report = new ContainerValidationReport();
    report.setValidationPolicy(extractValidationPolicy());
    report.setValidationTime(new Date());
    report.setSignaturesCount(signatureValidationData.size());
    report.setValidSignaturesCount(extractValidSignaturesCount());
    report.setSignatures(createSignatureValidationReports());
    report.setTimestampTokens(createTimestampValidationReports());
    report.setContainerErrors(toExceptionMessages(containerErrors));
    report.setContainerWarnings(toExceptionMessages(containerWarnings));
    return report;
  }

  private String generateNewXmlReport() {
    logger.debug("Generating a new XML validation report");
    ContainerValidationReport report = generateNewValidationReport();
    return createFormattedXmlString(report);
  }

  private List<SignatureValidationReport> createSignatureValidationReports() {
    return signatureValidationData.stream()
            .map(SignatureValidationReportCreator::create)
            .collect(Collectors.toCollection(ArrayList::new));
  }

  private List<TimestampValidationReport> createTimestampValidationReports() {
    return timestampValidationData.stream()
            .map(TimestampValidationReportCreator::create)
            .collect(Collectors.toCollection(ArrayList::new));
  }

  private XmlValidationPolicy extractValidationPolicy() {
    return Stream.concat(
            signatureValidationData.stream().map(data -> data.getReport().getReports()),
            timestampValidationData.stream().map(TimestampValidationData::getEncapsulatingReports)
    )
            .map(Reports::getSimpleReportJaxb)
            .map(XmlSimpleReport::getValidationPolicy)
            .filter(Objects::nonNull)
            .findFirst()
            .orElse(null);
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

  private static List<String> toExceptionMessages(List<DigiDoc4JException> exceptions) {
    return exceptions.stream().map(DigiDoc4JException::getMessage).collect(Collectors.toList());
  }

  public static String createFormattedXmlString(ContainerValidationReport simpleReport) {
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
