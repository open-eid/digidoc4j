/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.model.DSSDocument;
import org.digidoc4j.Timestamp;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Utility class for handling CAdES timestamp tokens for ASiC containers.
 */
public final class TimestampUtils {

  /**
   * Finds the last timestamp from the list of provided {@link AsicContainerTimestamp}s by first finding the timestamps
   * that are not covered by any other timestamp from the provided list, and then returning the timestamp with the
   * latest creation date.
   * 
   * @param timestamps list of timestamps to find the last timestamp from
   * @return last timestamp from the provided list of timestamps
   * @param <T> type of timestamps to process
   * 
   * @see #isTimestampCoveredByTimestamp(AsicContainerTimestamp, List) 
   */
  public static <T extends AsicContainerTimestamp> T findLastTimestamp(List<T> timestamps) {
    return timestamps.stream()
            .filter(ts -> !isTimestampCoveredByTimestamp(ts, timestamps))
            .max(Comparator.comparing(Timestamp::getCreationTime))
            .orElse(null);
  }

  /**
   * Returns {@code true} if a manifest of any of the provided timestamps contains an entry with the name of either
   * the specified timestamp or its manifest, otherwise {@code false}.
   *
   * @param timestamp timestamp to check
   * @param timestamps list of timestamps
   * @return {@code true} if the specified timestamp or its manifest is referenced in any of the manifests of the
   * provided timestamps, otherwise {@code false}
   * 
   * @see #isEntryCoveredByTimestamp(String, List)
   */
  public static boolean isTimestampCoveredByTimestamp(AsicContainerTimestamp timestamp, List<? extends AsicContainerTimestamp> timestamps) {
    if (isEntryCoveredByTimestamp(timestamp.getTimestampDocument().getName(), timestamps)) {
      return true;
    }
    AsicArchiveManifest manifest = timestamp.getTimestampManifest();
    return (manifest != null) && isEntryCoveredByTimestamp(manifest.getManifestDocument().getName(), timestamps);
  }

  /**
   * Returns {@code true} if a manifest of any of the provided timestamps contains an entry with the specified name,
   * otherwise {@code false}.
   *
   * @param entryName name of the entry to check
   * @param timestamps list of timestamps
   * @return {@code true} if the specified entry name is referenced in any of the manifests of the provided timestamps,
   * otherwise {@code false}
   */
  public static boolean isEntryCoveredByTimestamp(String entryName, List<? extends AsicContainerTimestamp> timestamps) {
    return timestamps.stream()
            .map(AsicContainerTimestamp::getTimestampManifest)
            .filter(Objects::nonNull)
            .map(AsicArchiveManifest::getNonNullEntryNames)
            .anyMatch(entries -> entries.contains(entryName));
  }

  /**
   * Returns the set of non-null names of the provided {@link AsicContainerTimestamp}s and their manifest files.
   *
   * @param timestamps list of timestamps
   * @return set of timestamps and their manifests names
   */
  public static Set<String> getTimestampAndManifestNames(List<? extends AsicContainerTimestamp> timestamps) {
    return timestamps.stream()
            .flatMap(ts -> Stream.concat(
                    Stream.of(ts.getTimestampDocument()),
                    Optional
                            .ofNullable(ts.getTimestampManifest())
                            .map(AsicArchiveManifest::getManifestDocument)
                            .map(Stream::of)
                            .orElseGet(Stream::empty)
            ))
            .map(DSSDocument::getName)
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
  }

  private TimestampUtils() {
  }

}
