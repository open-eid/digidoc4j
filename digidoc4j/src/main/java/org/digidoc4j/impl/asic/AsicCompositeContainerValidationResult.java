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

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.report.ContainerValidationReport;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A composite validation result that aggregates the contents of both an arbitrary nested container
 * and a nesting ASiC container.
 */
public class AsicCompositeContainerValidationResult implements ContainerValidationResult {

  private final AsicContainerValidationResult nestingContainerValidationResult;
  private final ContainerValidationResult nestedContainerValidationResult;

  private transient String report;

  public AsicCompositeContainerValidationResult(
          AsicContainerValidationResult nestingContainerValidationResult,
          ContainerValidationResult nestedContainerValidationResult
  ) {
    this.nestingContainerValidationResult = Objects.requireNonNull(nestingContainerValidationResult);
    this.nestedContainerValidationResult = Objects.requireNonNull(nestedContainerValidationResult);
  }

  public ContainerValidationResult getNestingContainerValidationResult() {
    return nestingContainerValidationResult;
  }

  public ContainerValidationResult getNestedContainerValidationResult() {
    return nestedContainerValidationResult;
  }

  @Override
  public boolean isValid() {
    return nestedContainerValidationResult.isValid() && nestingContainerValidationResult.isValid();
  }

  @Override
  public boolean hasWarnings() {
    return nestedContainerValidationResult.hasWarnings() || nestingContainerValidationResult.hasWarnings();
  }

  @Override
  public List<DigiDoc4JException> getErrors() {
    return getConcatenatedUnmodifiableList(ValidationResult::getErrors);
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    return getConcatenatedUnmodifiableList(ValidationResult::getWarnings);
  }

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return getConcatenatedUnmodifiableList(ContainerValidationResult::getContainerErrors);
  }

  @Override
  public List<DigiDoc4JException> getContainerWarnings() {
    return getConcatenatedUnmodifiableList(ContainerValidationResult::getContainerWarnings);
  }

  @Override
  public List<SimpleReport> getSimpleReports() {
    return getConcatenatedUnmodifiableList(SignatureValidationResult::getSimpleReports);
  }

  @Override
  public List<String> getSignatureIdList() {
    return getConcatenatedUnmodifiableList(ContainerValidationResult::getSignatureIdList);
  }

  @Override
  public List<String> getTimestampIdList() {
    return getConcatenatedUnmodifiableList(ContainerValidationResult::getTimestampIdList);
  }

  @Override
  public List<SignatureValidationReport> getSignatureReports() {
    return getConcatenatedUnmodifiableList(SignatureValidationResult::getSignatureReports);
  }

  @Override
  public List<TimestampValidationReport> getTimestampReports() {
    return getConcatenatedUnmodifiableList(ContainerValidationResult::getTimestampReports);
  }

  @Override
  public Indication getIndication(String tokenId) {
    return getFirstNonNull(validationResult -> validationResult.getIndication(tokenId));
  }

  @Override
  public SubIndication getSubIndication(String tokenId) {
    return getFirstNonNull(validationResult -> validationResult.getSubIndication(tokenId));
  }

  @Override
  public ValidationResult getValidationResult(String tokenId) {
    return getFirstNonNull(validationResult -> validationResult.getValidationResult(tokenId));
  }

  @Override
  public SignatureQualification getSignatureQualification(String signatureId) {
    return getFirstNonNull(validationResult -> validationResult.getSignatureQualification(signatureId));
  }

  @Override
  public TimestampQualification getTimestampQualification(String timestampId) {
    return getFirstNonNull(validationResult -> validationResult.getTimestampQualification(timestampId));
  }

  @Override
  public String getReport() {
    if (report == null) {
      report = generateReport();
    }

    return report;
  }

  @Override
  public void saveXmlReports(Path directory) {
    DSSUtils.saveToFile(
            getReport().getBytes(StandardCharsets.UTF_8),
            directory.resolve("validationReport.xml").toFile()
    );
    // Each container validation result saves their own "validationReport.xml" file, as well as other DSS reports.
    // Place reports of nested and nesting container validation results into separate subdirectories in order to avoid
    // any validation result to overwrite reports of other validation results.
    nestedContainerValidationResult.saveXmlReports(directory.resolve("nestedContainer"));
    nestingContainerValidationResult.saveXmlReports(directory.resolve("nestingContainer"));
  }

  private String generateReport() {
    AsicValidationReportBuilder nestingValidationReportBuilder = nestingContainerValidationResult.getValidationReportBuilder();
    ContainerValidationReport containerValidationReport = nestingValidationReportBuilder.generateNewValidationReport();

    containerValidationReport.setSignatures(getSignatureReports());
    containerValidationReport.setTimestampTokens(getTimestampReports());
    containerValidationReport.setContainerErrors(getContainerErrors().stream()
            .map(Throwable::getMessage)
            .collect(Collectors.toList())
    );

    containerValidationReport.setSignaturesCount(getSignatureIdList().size());
    containerValidationReport.setValidSignaturesCount((int) getSignatureIdList().stream()
            .map(this::getValidationResult)
            .filter(ValidationResult::isValid)
            .count());

    return AsicValidationReportBuilder.createFormattedXmlString(containerValidationReport);
  }

  private <T> List<T> getConcatenatedUnmodifiableList(Function<ContainerValidationResult, List<T>> extractor) {
    List<T> nestedValidationResultList = extractor.apply(nestedContainerValidationResult);
    List<T> nestingValidationResultList = extractor.apply(nestingContainerValidationResult);

    int nestedValidationResultListSize = CollectionUtils.size(nestedValidationResultList);
    int nestingValidationResultListSize = CollectionUtils.size(nestingValidationResultList);

    if (nestedValidationResultListSize + nestingValidationResultListSize == 0) {
      return Collections.emptyList();
    }

    List<T> concatenatedList = new ArrayList<>(nestedValidationResultListSize + nestingValidationResultListSize);
    if (nestedValidationResultListSize > 0) {
      concatenatedList.addAll(nestedValidationResultList);
    }
    if (nestingValidationResultListSize > 0) {
      concatenatedList.addAll(nestingValidationResultList);
    }
    return Collections.unmodifiableList(concatenatedList);
  }

  private <T> T getFirstNonNull(Function<ContainerValidationResult, T> extractor) {
    return Stream
            .of(nestedContainerValidationResult, nestingContainerValidationResult)
            .map(extractor)
            .filter(Objects::nonNull)
            .findFirst()
            .orElse(null);
  }

}
