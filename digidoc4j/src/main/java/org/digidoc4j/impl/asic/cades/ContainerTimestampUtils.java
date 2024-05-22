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

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.lang3.StringUtils;

import java.util.Collection;
import java.util.Comparator;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Utility class for handling CAdES timestamp tokens for ASiC containers.
 */
public final class ContainerTimestampUtils {

  private static final Pattern TIMESTAMP_FILE_PATTERN = Pattern.compile(
          '^' + ASiCUtils.META_INF_FOLDER + "\\w+\\" + ASiCUtils.TST_EXTENSION + '$'
  );
  private static final Pattern MANIFEST_FILE_PATTERN = Pattern.compile(
          '^' + ASiCUtils.META_INF_FOLDER + ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME + "\\d*\\" + ASiCUtils.XML_EXTENSION + '$'
  );

  /**
   * Finds the last timestamp from the collection of provided {@link TimestampAndManifestPair}s by first finding the
   * timestamp entities that are not covered by any other timestamp entity from the provided list, and then returning
   * the timestamp entity with the latest creation date.
   * 
   * @param timestamps collection of timestamp entities to find the last timestamp entity from
   * @return last timestamp entity from the provided collection of timestamp entities
   * @param <T> type of timestamp entities to process
   * 
   * @see #isTimestampCoveredByTimestamp(TimestampAndManifestPair, Collection)
   */
  public static <T extends TimestampAndManifestPair> T findLastTimestamp(Collection<T> timestamps) {
    return timestamps.stream()
            .filter(ts -> !isTimestampCoveredByTimestamp(ts, timestamps))
            .max(Comparator.comparing(ts -> ts.getCadesTimestamp().getCreationTime()))
            .orElse(null);
  }

  /**
   * Returns {@code true} if a manifest of any of the provided timestamp entities contains an entry with the name of
   * either the specified timestamp entity or its manifest, otherwise {@code false}.
   *
   * @param timestamp timestamp entity to check
   * @param timestamps collection of timestamp entities
   * @return {@code true} if the specified timestamp entity or its manifest is referenced in any of the manifests of the
   * provided timestamp entities, otherwise {@code false}
   * 
   * @see #isEntryCoveredByTimestamp(String, Collection)
   */
  public static boolean isTimestampCoveredByTimestamp(TimestampAndManifestPair timestamp, Collection<? extends TimestampAndManifestPair> timestamps) {
    if (isEntryCoveredByTimestamp(timestamp.getCadesTimestamp().getTimestampDocument().getName(), timestamps)) {
      return true;
    }
    AsicArchiveManifest manifest = timestamp.getArchiveManifest();
    return (manifest != null) && isEntryCoveredByTimestamp(manifest.getManifestDocument().getName(), timestamps);
  }

  /**
   * Returns {@code true} if a manifest of any of the provided timestamp entities contains an entry with the specified
   * name, otherwise {@code false}.
   *
   * @param entryName name of the entry to check
   * @param timestamps collection of timestamp entities
   * @return {@code true} if the specified entry name is referenced in any of the manifests of the provided timestamp
   * entities, otherwise {@code false}
   */
  public static boolean isEntryCoveredByTimestamp(String entryName, Collection<? extends TimestampAndManifestPair> timestamps) {
    return timestamps.stream()
            .map(TimestampAndManifestPair::getArchiveManifest)
            .filter(Objects::nonNull)
            .map(AsicArchiveManifest::getNonNullEntryNames)
            .anyMatch(entries -> entries.contains(entryName));
  }

  /**
   * Returns the set of non-null names of the provided timestamp entities and their manifest files.
   *
   * @param timestamps collection of timestamp entities
   * @return set of timestamp entities' and their manifests' names
   */
  public static Set<String> getTimestampAndManifestNames(Collection<? extends TimestampAndManifestPair> timestamps) {
    return timestamps.stream()
            .flatMap(ts -> Stream.concat(
                    Stream.of(ts.getCadesTimestamp().getTimestampDocument()),
                    Optional
                            .ofNullable(ts.getArchiveManifest())
                            .map(AsicArchiveManifest::getManifestDocument)
                            .map(Stream::of)
                            .orElseGet(Stream::empty)
            ))
            .map(DSSDocument::getName)
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
  }

  /**
   * Tests whether the specified file name matches the pattern: {@code META-INF/\w+\.tst}.
   *
   * @param fileName file name to test
   * @return {@code true} if the specified file name represents a timestamp token file, otherwise {@code false}
   */
  public static boolean isTimestampFileName(String fileName) {
    return StringUtils.isNotBlank(fileName) && TIMESTAMP_FILE_PATTERN.matcher(fileName).matches();
  }

  /**
   * Tests whether the specified file name matches the pattern: {@code META-INF/ASiCArchiveManifest\d*\.xml}.
   *
   * @param fileName file name to test
   * @return {@code true} if the specified file name represents an ASiCArchiveManifest file, otherwise {@code false}
   */
  public static boolean isArchiveManifestFileName(String fileName) {
    return StringUtils.isNotBlank(fileName) && MANIFEST_FILE_PATTERN.matcher(fileName).matches();
  }

  private ContainerTimestampUtils() {
  }

}
