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
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.impl.AbstractContainerValidationResult;

import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Validation result information.
 * <p>
 * For BDOC the ValidationResult contains only information for the first signature of each signature XML file
 */
public class AsicContainerValidationResult extends AbstractContainerValidationResult implements ContainerValidationResult {

  private Map<String, String> signatureIdMap = Collections.emptyMap();
  private AsicValidationReportBuilder validationReportBuilder;

  @Override
  public Indication getIndication(String tokenId) {
    return findFromSimpleReportsByIdOrMappedId(ensureTokenIdNotNull(tokenId), SimpleReport::getIndication);
  }

  @Override
  public SubIndication getSubIndication(String tokenId) {
    return findFromSimpleReportsByIdOrMappedId(ensureTokenIdNotNull(tokenId), SimpleReport::getSubIndication);
  }

  @Override
  public SignatureQualification getSignatureQualification(String signatureId) {
    return findFromSimpleReportsByIdOrMappedId(ensureTokenIdNotNull(signatureId), (report, id) -> {
      // In DSS 6.0, SimpleReport::getSignatureQualification returns NA if the report does not contain such a signature
      return report.getSignatureIdList().contains(id) ? report.getSignatureQualification(id) : null;
    });
  }

  @Override
  public TimestampQualification getTimestampQualification(String timestampId) {
    ensureTokenIdNotNull(timestampId);
    return findFromSimpleReports(report -> report.getTimestampQualification(timestampId));
  }

  /**
   * Save DSS validation reports in given directory.
   *
   * @param directory Directory where to save XML files. When null then do nothing.
   */
  @Override
  public void saveXmlReports(Path directory) {
    if (this.validationReportBuilder != null) {
      if (directory != null) {
        this.validationReportBuilder.saveXmlReports(directory);
      }
    }
  }

  /**
   * Set report validationReportBuilder.
   *
   * @param validationReportBuilder Report validationReportBuilder to use
   */
  public void generate(AsicValidationReportBuilder validationReportBuilder) {
    if (validationReportBuilder == null) {
      throw new IllegalArgumentException("Builder is unset");
    }
    this.validationReportBuilder = validationReportBuilder;
    this.buildResult();
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected String getResultName() {
    return "ASiC container";
  }

  AsicValidationReportBuilder getValidationReportBuilder() {
    return validationReportBuilder;
  }

  private void buildResult() {
    if (validationReportBuilder != null) {
      report = validationReportBuilder.buildXmlReport();
      signatureReports = validationReportBuilder.buildSignatureValidationReports();
      timestampReports = validationReportBuilder.buildTimestampValidationReports();
      simpleReports = validationReportBuilder.buildAllSimpleReports();
      signatureIdMap = validationReportBuilder.buildSignatureIdMap();
    }
  }

  private <T> T findFromSimpleReportsByIdOrMappedId(String tokenId, BiFunction<SimpleReport, String, T> extractor) {
    return Optional
            .ofNullable(findFromSimpleReports(report -> extractor.apply(report, tokenId)))
            .orElseGet(() -> Optional
                    .ofNullable(signatureIdMap.get(tokenId))
                    .map(mappedId -> findFromSimpleReports(report -> extractor.apply(report, mappedId)))
                    .orElse(null));
  }

  private <T> T findFromSimpleReports(Function<SimpleReport, T> extractor) {
    for (SimpleReport report : simpleReports) {
      T result = extractor.apply(report);
      if (result != null) {
        return result;
      }
    }
    return null;
  }

  private static String ensureTokenIdNotNull(String tokenId) {
    return Objects.requireNonNull(tokenId, "Token ID cannot be null");
  }

}
