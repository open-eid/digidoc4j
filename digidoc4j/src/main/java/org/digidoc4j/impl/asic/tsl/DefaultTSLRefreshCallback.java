/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.tsl;

import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;
import eu.europa.esig.dss.spi.tsl.InfoRecord;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.TSLRefreshCallback;
import org.digidoc4j.exceptions.TslDownloadException;
import org.digidoc4j.exceptions.TslParsingException;
import org.digidoc4j.exceptions.TslRefreshException;
import org.digidoc4j.exceptions.TslValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Default implementation of the {@link TSLRefreshCallback}.
 */
public class DefaultTSLRefreshCallback implements TSLRefreshCallback {

  private static final Logger LOGGER = LoggerFactory.getLogger(DefaultTSLRefreshCallback.class);

  private static final String LoTL = "LoTL";
  private static final String Pivot_LoTL = "Pivot LoTL";
  private static final String TL = "TL";

  private final Configuration configuration;

  /**
   * Creates an instance of this callback with the specified configuration.
   *
   * @param configuration configuration to use
   */
  public DefaultTSLRefreshCallback(Configuration configuration) {
    this.configuration = Objects.requireNonNull(configuration);
  }

  /**
   * Ensures the state of the TSL and either throws an exception or returns {@code true}.
   *
   * @param summary the information about the state of the TSL
   *
   * @return always {@code true}, unless an exception is thrown
   *
   * @throws TslRefreshException if:<ul>
   *     <li>the summary contains no information about any LoTL-s</li>
   *     <li>a LoTL has failed to download, parse or validate</li>
   *     <li>all trusted lists in a LoTL have failed to download, parse or validate</li>
   *     <li>the trusted list of any required territory has failed to download, parse or validate</li>
   * </ul>
   *
   * @see Configuration#getRequiredTerritories()
   * @see Configuration#setRequiredTerritories(String...)
   */
  @Override
  public boolean ensureTSLState(TLValidationJobSummary summary) {
    if (CollectionUtils.isEmpty(summary.getLOTLInfos())) {
      throw new TslRefreshException("No TSL refresh info found!");
    }

    for (LOTLInfo lotlInfo : summary.getLOTLInfos()) {
      ensureLOTLState(lotlInfo);
    }

    return true;
  }

  private void ensureLOTLState(LOTLInfo lotlInfo) {
    List<TslRefreshException> lotlErrors = validateState(lotlInfo, LoTL);
    if (CollectionUtils.isNotEmpty(lotlErrors)) {
      Iterator<TslRefreshException> iterator = lotlErrors.iterator();
      TslRefreshException toThrow = iterator.next();
      while (iterator.hasNext()) {
        toThrow.addSuppressed(iterator.next());
      }
      throw toThrow;
    }

    Optional.ofNullable(lotlInfo.getPivotInfos())
            .map(List::stream).orElseGet(Stream::empty)
            .forEach(DefaultTSLRefreshCallback::checkPivotState);

    ensureStateOfTLsOfLOTL(lotlInfo);
  }

  private void ensureStateOfTLsOfLOTL(LOTLInfo lotlInfo) {
    Map<TslRefreshException, TLInfo> tlExceptions = new LinkedHashMap<>();
    boolean hasValidTrustedList = false;

    if (CollectionUtils.isNotEmpty(lotlInfo.getTLInfos())) {
      for (TLInfo tlInfo : lotlInfo.getTLInfos()) {
        List<TslRefreshException> tlErrors = validateState(tlInfo, TL);
        if (CollectionUtils.isNotEmpty(tlErrors)) {
          tlErrors.forEach(exception -> tlExceptions.put(exception, tlInfo));
        } else {
          hasValidTrustedList = true;
        }
      }
    }

    if (hasValidTrustedList) {
      ensureStateOfTLsOfRequiredTerritories(lotlInfo.getTLInfos(), tlExceptions);
      tlExceptions.keySet().forEach(DefaultTSLRefreshCallback::logExceptionMessageAsWarningIfExists);
    } else {
      String name = augmentEntityNameWithTerritoryIfPresent(LoTL, lotlInfo);
      String message = String.format("Failed to load any trusted lists for %s: %s", name, lotlInfo.getUrl());
      throwTslRefreshException(message, tlExceptions.keySet());
    }
  }

  private void ensureStateOfTLsOfRequiredTerritories(List<TLInfo> tlInfoList, Map<TslRefreshException, TLInfo> tlExceptions) {
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    if (CollectionUtils.isEmpty(requiredTerritories)) {
      return;
    }

    List<String> trustedTerritories = configuration.getTrustedTerritories();
    boolean trustedCheckRequired = CollectionUtils.isNotEmpty(trustedTerritories);
    List<String> failedRequiredTerritories = new ArrayList<>();

    for (String requiredTerritory : requiredTerritories) {
      if (trustedCheckRequired && !trustedTerritories.contains(requiredTerritory)) {
        // If this is not a trusted territory, then skip it
        continue;
      }
      TLInfo territoryInfo = tlInfoList.stream()
              .filter(tlInfoTerritoryFilter(requiredTerritory))
              .findFirst().orElse(null);
      if (territoryInfo != null && !tlExceptions.containsValue(territoryInfo)) {
        // If info exists for this territory and there are no exceptions related to the info, then skip it
        continue;
      }
      failedRequiredTerritories.add(requiredTerritory);
    }

    if (CollectionUtils.isNotEmpty(failedRequiredTerritories)) {
      String message = failedRequiredTerritories.stream().collect(Collectors.joining(
             ", ", "Failed to load trusted lists for required territories: ", StringUtils.EMPTY
      ));
      throwTslRefreshException(message, tlExceptions.keySet());
    }
  }

  private static List<TslRefreshException> validateState(TLInfo tlInfo, String entityName) {
    entityName = augmentEntityNameWithTerritoryIfPresent(entityName, tlInfo);

    TslRefreshException downloadException = validateDownloadState(tlInfo.getDownloadCacheInfo(), entityName, tlInfo.getUrl());
    TslRefreshException parsingException = validateParsingState(tlInfo.getParsingCacheInfo(), entityName, tlInfo.getUrl());
    TslRefreshException validationException = validateValidationState(tlInfo.getValidationCacheInfo(), entityName, tlInfo.getUrl());

    return Stream.of(downloadException, parsingException, validationException)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
  }

  private static void checkPivotState(PivotInfo pivotInfo) {
    String entityName = augmentEntityNameWithTerritoryIfPresent(Pivot_LoTL, pivotInfo);
    logExceptionMessageAsWarningIfExists(validateDownloadState(pivotInfo.getDownloadCacheInfo(), entityName, pivotInfo.getUrl()));
    logExceptionMessageAsWarningIfExists(validateParsingState(pivotInfo.getParsingCacheInfo(), entityName, pivotInfo.getUrl()));
    logExceptionMessageAsWarningIfExists(validateValidationState(pivotInfo.getValidationCacheInfo(), entityName, pivotInfo.getUrl()));
  }

  private static String augmentEntityNameWithTerritoryIfPresent(String entityName, TLInfo tlInfo) {
    return Optional.ofNullable(getTerritory(tlInfo))
            .filter(StringUtils::isNotBlank)
            .map(territory -> String.format("<%s> %s", territory, entityName))
            .orElse(entityName);
  }

  private static TslDownloadException validateDownloadState(DownloadInfoRecord downloadInfo, String entityName, String url) {
    if (downloadInfo == null) {
      String message = String.format("No download info found for %s: %s", entityName, url);
      return new TslDownloadException(message);
    } else if (downloadInfo.isError()) {
      String message = String.format("Failed to download %s: %s", entityName, url);
      return Optional.ofNullable(createCauseIfExceptionMessageExists(downloadInfo, TslDownloadException::new))
              .map(cause -> new TslDownloadException(message, cause))
              .orElseGet(() -> new TslDownloadException(message));
    } else if (downloadInfo.isRefreshNeeded()) {
      String message = String.format("(Re)download needed for %s: %s", entityName, url);
      return new TslDownloadException(message);
    } else if (!downloadInfo.isSynchronized()) {
      String message = String.format("Unexpected download status '%s' for %s: %s", downloadInfo.getStatusName(), entityName, url);
      return new TslDownloadException(message);
    }
    return null;
  }

  private static TslParsingException validateParsingState(ParsingInfoRecord parsingInfo, String entityName, String url) {
    if (parsingInfo == null) {
      String message = String.format("No parsing info found for %s: %s", entityName, url);
      return new TslParsingException(message);
    } else if (parsingInfo.isError()) {
      String message = String.format("Failed to parse %s: %s", entityName, url);
      return Optional.ofNullable(createCauseIfExceptionMessageExists(parsingInfo, TslParsingException::new))
              .map(cause -> new TslParsingException(message, cause))
              .orElseGet(() -> new TslParsingException(message));
    } else if (parsingInfo.isRefreshNeeded()) {
      String message = String.format("(Re)parsing needed for %s: %s", entityName, url);
      return new TslParsingException(message);
    } else if (!parsingInfo.isSynchronized()) {
      String message = String.format("Unexpected parsing status '%s' for %s: %s", parsingInfo.getStatusName(), entityName, url);
      return new TslParsingException(message);
    }
    return null;
  }

  private static TslValidationException validateValidationState(ValidationInfoRecord validationInfo, String entityName, String url) {
    if (validationInfo == null) {
      String message = String.format("No validation info found for %s: %s", entityName, url);
      return new TslValidationException(message);
    } else if (validationInfo.isError()) {
      String message = String.format("Failed to validate %s: %s", entityName, url);
      return Optional.ofNullable(createCauseIfExceptionMessageExists(validationInfo, TslValidationException::new))
              .map(cause -> new TslValidationException(message, cause))
              .orElseGet(() -> new TslValidationException(message));
    } else if (validationInfo.getIndication() != null && !validationInfo.isValid()) {
      String message = String.format("Failed to validate %s: %s", entityName, url);
      StringBuilder causeMessage = new StringBuilder(entityName).append(" validation failed; indication: ").append(validationInfo.getIndication());
      Optional.ofNullable(validationInfo.getSubIndication()).ifPresent(subIndication -> causeMessage.append("; sub-indication: ").append(subIndication));
      return new TslValidationException(message, new TslValidationException(causeMessage.toString()));
    } else if (validationInfo.isRefreshNeeded()) {
      String message = String.format("(Re)validation needed for %s: %s", entityName, url);
      return new TslValidationException(message);
    } else if (!validationInfo.isSynchronized()) {
      String message = String.format("Unexpected validation status '%s' for %s: %s", validationInfo.getStatusName(), entityName, url);
      return new TslValidationException(message);
    }
    return null;
  }

  private static String getTerritory(TLInfo tlInfo) {
    return Optional.ofNullable(tlInfo.getParsingCacheInfo()).map(ParsingInfoRecord::getTerritory).orElse(null);
  }

  private static Predicate<TLInfo> tlInfoTerritoryFilter(String territory) {
    return tlInfo -> Optional.ofNullable(getTerritory(tlInfo)).map(territory::equals).orElse(Boolean.FALSE);
  }

  private static TslRefreshException createCauseIfExceptionMessageExists(InfoRecord infoRecord, Function<String, TslRefreshException> exceptionFactory) {
    return Optional.ofNullable(infoRecord.getExceptionMessage()).map(exceptionFactory).orElse(null);
  }

  private static void throwTslRefreshException(String message, Collection<TslRefreshException> possibleCauses) {
    if (possibleCauses.size() == 1) {
      throw new TslRefreshException(message, possibleCauses.iterator().next());
    } else {
      TslRefreshException tslException = new TslRefreshException(message);
      possibleCauses.forEach(tslException::addSuppressed);
      throw tslException;
    }
  }

  private static void logExceptionMessageAsWarningIfExists(TslRefreshException exception) {
    if (exception != null && exception.getCause() != null) {
      LOGGER.warn("{} - {}", exception.getMessage(), exception.getCause().getMessage());
    } else if (exception != null) {
      LOGGER.warn(exception.getMessage());
    }
  }

}
