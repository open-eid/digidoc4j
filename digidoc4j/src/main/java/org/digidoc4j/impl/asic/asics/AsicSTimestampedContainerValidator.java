/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.collections4.CollectionUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.Timestamp;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.DataFilesValidationUtils;
import org.digidoc4j.impl.SimpleValidationResult;
import org.digidoc4j.impl.asic.AsicValidationReportBuilder;
import org.digidoc4j.impl.asic.TimeStampContainerValidationResult;
import org.digidoc4j.impl.asic.cades.TimestampValidationData;
import org.digidoc4j.impl.asic.validation.ReportedMessagesExtractor;
import org.digidoc4j.utils.DateUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A validator for ASiC-S containers with timestamp tokens.
 */
public class AsicSTimestampedContainerValidator {

  private final AsicSContainer asicsContainer;
  private final Date validationTime;

  /**
   * Creates an instance of a validator with current validation time.
   *
   * @param asicsContainer ASiC-S container to validate
   */
  public AsicSTimestampedContainerValidator(AsicSContainer asicsContainer) {
    this(asicsContainer, new Date());
  }

  /**
   * Creates an instance of a validator with specified validation time.
   *
   * @param validationTime validation time
   * @param asicsContainer ASiC-S container to validate
   */
  public AsicSTimestampedContainerValidator(AsicSContainer asicsContainer, Date validationTime) {
    this.asicsContainer = Objects.requireNonNull(asicsContainer);
    this.validationTime = validationTime;
  }

  /**
   * Validate the current state of this validator and return an instance of {@link ContainerValidationResult}.
   *
   * @return container validation result
   */
  public ContainerValidationResult validate() {
    Reports reports = new AsicSTimestampsValidationReportGenerator(asicsContainer).generateReports(validationTime);
    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);
    return createValidationResult(reports);
  }

  private AsicSTimestampedContainerValidationResult createValidationResult(Reports reports) {
    AsicSTimestampedContainerValidationResult result = isLegacyValidationResultSupported()
            ? createLegacyValidationResult()
            : new AsicSTimestampedContainerValidationResult();

    List<TimestampValidationData> timestampValidationData = extractTimestampValidationData(reports);

    result.setErrors(collectExceptions(timestampValidationData, ValidationResult::getErrors));
    result.setWarnings(collectExceptions(timestampValidationData, ValidationResult::getWarnings));
    TimestampNotGrantedValidationUtils.addContainerWarningIfNotGrantedTimestampExists(result);
    addDataFilesWarningsTo(result);

    result.generate(new AsicValidationReportBuilder(
            Collections.emptyList(),
            timestampValidationData,
            result.getContainerErrors(),
            result.getContainerWarnings()
    ));

    return result;
  }

  private void addDataFilesWarningsTo(AsicSTimestampedContainerValidationResult containerValidationResult) {
    Optional
            .of(asicsContainer.getDataFiles())
            .filter(CollectionUtils::isNotEmpty)
            .map(DataFilesValidationUtils::getExceptionsForEmptyDataFiles)
            .filter(CollectionUtils::isNotEmpty)
            .ifPresent(dataFilesWarnings -> {
              containerValidationResult.addContainerWarnings(dataFilesWarnings);
              containerValidationResult.addWarnings(dataFilesWarnings);
            });
  }

  private static List<TimestampValidationData> extractTimestampValidationData(Reports reports) {
    return reports.getDiagnosticData().getTimestampsByType(TimestampType.CONTAINER_TIMESTAMP).stream()
            .map(t -> createTimestampValidationData(t.getId(), reports))
            .collect(Collectors.toList());
  }

  private static TimestampValidationData createTimestampValidationData(String id, Reports reports) {
    SimpleValidationResult validationResult = new SimpleValidationResult("Timestamp Token");
    ReportedMessagesExtractor messagesExtractor = new ReportedMessagesExtractor(reports);

    validationResult.setErrors(ReportedMessagesExtractor.collectErrorsAsExceptions(
            messagesExtractor.extractReportedTokenErrors(id)
    ));
    validationResult.setWarnings(ReportedMessagesExtractor.collectWarningsAsExceptions(
            messagesExtractor.extractReportedTokenWarnings(id)
    ));

    return new TimestampValidationData(id, reports, validationResult);
  }

  private static List<DigiDoc4JException> collectExceptions(
          List<TimestampValidationData> timestampValidationData,
          Function<ValidationResult, List<DigiDoc4JException>> exceptionMapper
  ) {
    return timestampValidationData.stream()
            .map(TimestampValidationData::getValidationResult)
            .flatMap(validationResult -> exceptionMapper.apply(validationResult).stream())
            .collect(Collectors.toCollection(ArrayList::new));
  }

  /**
   * Legacy {@link TimeStampContainerValidationResult} is supported only if the container contains a single timestamp
   * token of type {@link AsicSContainerTimestamp}.
   *
   * @return {@code true} if legacy validation result is support for the current container, {@code false} otherwise
   *
   * @deprecated Deprecated for removal. To be removed when {@link org.digidoc4j.impl.asic.TimeStampTokenValidator} and
   * {@link TimeStampContainerValidationResult} are no longer supported.
   */
  @Deprecated
  private boolean isLegacyValidationResultSupported() {
    List<Timestamp> timestamps = asicsContainer.getTimestamps();
    return CollectionUtils.size(timestamps) == 1 && timestamps.get(0) instanceof AsicSContainerTimestamp;
  }

  /**
   * Returns the legacy container validation result of type {@link TimeStampContainerValidationResult} for backwards
   * compatibility until the old format is supported.
   * Applicable only if {@link #isLegacyValidationResultSupported()} returns {@code true} (container contains only a
   * single timestamp token).
   *
   * @return legacy {@link TimeStampContainerValidationResult}
   *
   * @see org.digidoc4j.impl.asic.TimeStampTokenValidator
   *
   * @deprecated Deprecated for removal. To be removed when {@link org.digidoc4j.impl.asic.TimeStampTokenValidator} and
   * {@link TimeStampContainerValidationResult} are no longer supported.
   */
  @Deprecated
  private TimeStampContainerValidationResult createLegacyValidationResult() {
    AsicSContainerTimestamp timestamp = (AsicSContainerTimestamp) asicsContainer.getTimestamps().get(0);
    TimeStampContainerValidationResult legacyResult = new TimeStampContainerValidationResult();

    legacyResult.setTimeStampToken(timestamp.getTimeStampToken());
    legacyResult.setSignedTime(DateUtils.getDateFormatterWithGMTZone().format(timestamp.getCreationTime()));
    legacyResult.setSignedBy(Optional
            .ofNullable(timestamp.getTimeStampToken().getTimeStampInfo().getTsa())
            .map(GeneralName::getName)
            .filter(X500Name.class::isInstance)
            .map(X500Name.class::cast)
            .map(n -> n.getRDNs(BCStyle.CN)[0].getFirst().getValue())
            .map(IETFUtils::valueToString)
            .orElse(null));

    return legacyResult;
  }

}
