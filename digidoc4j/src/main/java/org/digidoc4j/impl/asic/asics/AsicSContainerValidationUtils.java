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

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.IllegalContainerContentException;
import org.digidoc4j.impl.asic.AsicEntry;
import org.digidoc4j.impl.asic.AsicParseResult;

import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Utility class for validating ASiC-S container contents.
 */
public final class AsicSContainerValidationUtils {

  /**
   * Pattern for matching "{@code META-INF/*signature*.p7s}"
   * where "{@code signature}" and "{@code p7s}" are case-insensitive.
   */
  private static final Pattern CAdES_SIGNATURE_RESERVED_FILENAME_PATTERN = Pattern.compile(
          ASiCUtils.META_INF_FOLDER + ".*(?i)signature.*\\.p7s"
  );
  /**
   * Pattern for matching "{@code META-INF/*signatures*.xml}"
   * where "{@code signatures}" and "{@code xml}" are case-insensitive.
   */
  private static final Pattern XAdES_SIGNATURES_RESERVED_FILENAME_PATTERN = Pattern.compile(
          ASiCUtils.META_INF_FOLDER + ".*(?i)signatures.*\\.xml"
  );
  /**
   * Pattern for matching "{@code META-INF/*timestamp*.tst}"
   * where "{@code timestamp}" and "{@code tst}" are case-insensitive.
   */
  private static final Pattern TIMESTAMP_TOKEN_RESERVED_FILENAME_PATTERN = Pattern.compile(
          ASiCUtils.META_INF_FOLDER + ".*(?i)timestamp.*\\.tst"
  );
  /**
   * Pattern for matching "{@code META-INF/evidencerecord.ers}" and "{@code META-INF/evidencerecord.xml}"
   * where "{@code evidencerecord}", "{@code ers}", and "{@code xml}" are case-insensitive.
   */
  private static final Pattern EVIDENCE_RECORD_RESERVED_FILENAME_PATTERN = Pattern.compile(
          ASiCUtils.META_INF_FOLDER + "(?i)evidencerecord\\.(ers|xml)"
  );

  /**
   * Validates the contents of the specified {@link AsicParseResult}, throwing {@link IllegalContainerContentException}
   * if any of the following rules are violated:
   * <ul>
   * <li>Mimetype must be "{@code application/vnd.etsi.asic-s+zip}".</li>
   * <li>Signatures and timestamps must not be present simultaneously.</li>
   * <li>No CAdES signature entries "{@code META-INF/*signature*.p7s}" must be present
   * (comparison of "{@code signature}" and "{@code p7s}" is case-insensitive).</li>
   * <li>No evidence record entries "{@code META-INF/evidencerecord.ers}" or "{@code META-INF/evidencerecord.xml}" must
   * be present(comparison of "{@code evicencerecord}", "{@code ers}" and "{@code xml}" is case-insensitive).</li>
   * <li>In case any signatures are present:</li>
   * <ul>
   *     <li>Exactly one data file must be present.</li>
   *     <li>No CAdES timestamp token entries "{@code META-INF/*timestamp*.tst}" must be present
   *     (comparison of "{@code timestamp}" and "{@code tst}" is case-insensitive).</li>
   * </ul>
   * <li>In case any timestamp tokens are present:</li>
   * <ul>
   *     <li>Exactly one data file must be present.</li>
   *     <li>No XAdES signature entries "{@code META-INF/*signatures*.xml}" must be present
   *     (comparison of "{@code signatures}" and "{@code xml}" is case-insensitive).</li>
   * </ul>
   * <li>In case no signatures nor timestamps are present:</li>
   * <ul>
   *     <li>No more than one data file can be present.</li>
   * </ul>
   * </ul>
   *
   * @param parseResult ASiC parse result to validate
   *
   * @throws IllegalContainerContentException if validation rules are violated
   */
  public static void validateContainerParseResult(AsicParseResult parseResult) {
    validateContainsSupportedMimeType(parseResult);

    boolean hasSignatures = CollectionUtils.isNotEmpty(parseResult.getSignatures());
    boolean hasTimestamps = CollectionUtils.isNotEmpty(parseResult.getTimestamps());

    if (hasSignatures && hasTimestamps) {
      throw new IllegalContainerContentException("ASiC-S container cannot contain signatures and timestamp tokens simultaneously");
    } else if (hasSignatures) {
      validateSignedContainerContents(parseResult);
    } else if (hasTimestamps) {
      validateTimestampedContainerContents(parseResult);
    } else {
      validateContainsNoMoreThanOneDataFile(parseResult);
    }

    validateContainsNoUnsupportedEntries(parseResult);
  }

  private static void validateSignedContainerContents(AsicParseResult parseResult) {
    if (CollectionUtils.size(parseResult.getDataFiles()) != 1) {
      throw new IllegalContainerContentException("Signed ASiC-S container must contain exactly one datafile");
    }
    checkContainsMatchingEntry(parseResult, TIMESTAMP_TOKEN_RESERVED_FILENAME_PATTERN, entry -> {
      throw new IllegalContainerContentException("Signed ASiC-S container cannot contain timestamp token entry: " + entry);
    });
  }

  private static void validateTimestampedContainerContents(AsicParseResult parseResult) {
    if (CollectionUtils.size(parseResult.getDataFiles()) != 1) {
      throw new IllegalContainerContentException("Timestamped ASiC-S container must contain exactly one datafile");
    }
    checkContainsMatchingEntry(parseResult, XAdES_SIGNATURES_RESERVED_FILENAME_PATTERN, entry -> {
      throw new IllegalContainerContentException("Timestamped ASiC-S container cannot contain signature entry: " + entry);
    });
  }

  private static void validateContainsSupportedMimeType(AsicParseResult parseResult) {
    if (!MimeTypeEnum.ASICS.getMimeTypeString().equals(parseResult.getMimeType())) {
      throw new IllegalContainerContentException("Invalid mimetype for ASiC-S container");
    }
  }

  private static void validateContainsNoUnsupportedEntries(AsicParseResult parseResult) {
    checkContainsMatchingEntry(parseResult, CAdES_SIGNATURE_RESERVED_FILENAME_PATTERN, entry -> {
      throw new IllegalContainerContentException("Unsupported CAdES signature entry: " + entry);
    });
    checkContainsMatchingEntry(parseResult, EVIDENCE_RECORD_RESERVED_FILENAME_PATTERN, entry -> {
      throw new IllegalContainerContentException("Unsupported evidence record entry: " + entry);
    });
  }

  private static void validateContainsNoMoreThanOneDataFile(AsicParseResult parseResult) {
    if (CollectionUtils.size(parseResult.getDataFiles()) > 1) {
      throw new IllegalContainerContentException("ASiC-S container cannot contain more than one datafile");
    }
  }

  private static void checkContainsMatchingEntry(AsicParseResult parseResult, Pattern pattern, Consumer<String> matchCallback) {
    if (CollectionUtils.isEmpty(parseResult.getAsicEntries())) {
      return;
    }
    for (AsicEntry entry : parseResult.getAsicEntries()) {
      String entryName = Optional.ofNullable(entry).map(AsicEntry::getName).orElse(null);
      if (StringUtils.isNotBlank(entryName) && pattern.matcher(entryName).matches()) {
        matchCallback.accept(entryName);
      }
    }
  }

  private AsicSContainerValidationUtils() {
  }

}
