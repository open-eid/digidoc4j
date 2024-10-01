/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Common container utilities.
 */
public final class ContainerUtils {

  public static final String DDOC_MIMETYPE_STRING = "application/x-ddoc";

  private static final Logger log = LoggerFactory.getLogger(ContainerUtils.class);

  /**
   * Returns the preferred mimetype string for the specified container, or {@code application/octet-stream} if no better
   * match is found.
   *
   * @param container container to get mimetype for
   * @return preferred mimetype string for the specified container, or {@code application/octet-stream}
   */
  public static String getMimeTypeStringFor(Container container) {
    return Optional
            .ofNullable(container)
            .map(Container::getType)
            .map(ContainerUtils::mapContainerTypeToMimeTypeString)
            .orElseGet(MimeTypeEnum.BINARY::getMimeTypeString);
  }

  /**
   * Returns {@code true} if the input is a ZIP container with a "mimetype" entry containing any of the specified
   * mimetype strings, otherwise {@code false}.
   * <p>This method checks:<ul>
   * <li>whether the input begins with the ZIP local file header; if not, {@code false} is returned immediately</li>
   * <li>whether the first file of the ZIP container is an uncompressed ASiC mimetype entry as specified in
   * https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf annex A.1;
   * if yes and the entry contains any of the specified mimetype strings, {@code true} is returned immediately</li>
   * <li>whether the input is readable using {@link java.util.zip.ZipInputStream} and it contains an ASiC mimetype entry
   * containing any of the specified mimetype strings</li>
   * </ul>
   * <p><b>NB:</b> This method may open the input stream multiple times!
   *
   * @param inputStreamSupplier supplier that opens and returns the stream of the input to check
   * @param allowedMimeTypeStrings list of allowed mimetype strings allowed in container "mimetype" entry
   * @return {@code true} if the input is a ZIP container with a "mimetype" entry containing any of the specified
   * mimetype strings, otherwise {@code false}
   * @throws IllegalArgumentException if no allowed mimetype strings are provided
   */
  public static boolean isAsicContainer(Supplier<InputStream> inputStreamSupplier, String... allowedMimeTypeStrings) {
    if (ArrayUtils.isEmpty(allowedMimeTypeStrings)) {
      throw new IllegalArgumentException("No allowed mimetype strings specified");
    }

    Set<byte[]> allowedMimeTypes = Stream.of(allowedMimeTypeStrings).distinct()
            .map(mts -> mts.getBytes(StandardCharsets.UTF_8))
            .collect(Collectors.toSet());

    try (InputStream inputStream = inputStreamSupplier.get()) {
      ZipLocalFileHeader zipHeader = ZipLocalFileHeader.readStaticHeaderPart(inputStream);
      if (isUncompressedMimeTypeEntry(zipHeader, inputStream)) {
        return isAsicMimeTypeEntry(zipHeader, inputStream, allowedMimeTypes);
      }
    } catch (EOFException | ZipLocalFileHeader.UnrecognizedSignatureException e) {
      log.debug("Unable to recognize input as a ZIP container: {}", e.getMessage());
      return false;
    } catch (Exception e) {
      log.debug("Failed to inspect input", e);
    }

    try (InputStream inputStream = inputStreamSupplier.get()) {
      return containsAsicMimeTypeEntry(inputStream, allowedMimeTypes);
    } catch (Exception e) {
      log.debug("Unable to parse input as ZIP container: {}", e.getMessage());
      return false;
    }
  }

  private static String mapContainerTypeToMimeTypeString(String containerType) {
    switch (containerType) {
      case Constant.ASICE_CONTAINER_TYPE:
      case Constant.BDOC_CONTAINER_TYPE:
        return MimeTypeEnum.ASICE.getMimeTypeString();
      case Constant.ASICS_CONTAINER_TYPE:
        return MimeTypeEnum.ASICS.getMimeTypeString();
      case Constant.DDOC_CONTAINER_TYPE:
        return DDOC_MIMETYPE_STRING;
      default:
        return null;
    }
  }

  private static boolean isUncompressedMimeTypeEntry(
          ZipLocalFileHeader zipHeader,
          InputStream inputStream
  ) throws IOException {
    if (
            zipHeader.getCompressionMethod() != ZipLocalFileHeader.COMPRESSION_METHOD_NONE
                    || zipHeader.getCompressedSize() != zipHeader.getUncompressedSize()
                    || zipHeader.getFileNameLength() != ASiCUtils.MIME_TYPE.length()
                    || zipHeader.getExtraFieldLength() != 0
    ) {
      return false;
    }
    try {
      byte[] fileNameBytes = zipHeader.readFileNameFrom(inputStream);
      return Arrays.equals(ASiCUtils.MIME_TYPE.getBytes(StandardCharsets.UTF_8), fileNameBytes);
    } catch (EOFException e) {
      log.debug("Failed to read mimetype entry name");
      return false;
    }
  }

  private static boolean isAsicMimeTypeEntry(
          ZipLocalFileHeader zipHeader,
          InputStream inputStream,
          Set<byte[]> allowedMimeTypes
  ) throws IOException {
    int mimeTypeLength = zipHeader.getUncompressedSize();

    if (allowedMimeTypes.stream().noneMatch(mt -> mt.length == mimeTypeLength)) {
      return false;
    }

    byte[] mimeTypeBytes = new byte[mimeTypeLength];
    if (IOUtils.read(inputStream, mimeTypeBytes, 0, mimeTypeLength) != mimeTypeLength) {
      return false;
    }
    return allowedMimeTypes.stream().anyMatch(mt -> Arrays.equals(mt, mimeTypeBytes));
  }

  private static boolean containsAsicMimeTypeEntry(
          InputStream inputStream,
          Set<byte[]> allowedMimeTypes
  ) throws IOException {
    int maxMimeTypeLength = allowedMimeTypes.stream().mapToInt(mt -> mt.length).max()
            .orElseThrow(() -> new IllegalArgumentException("No mimetypes specified"));

    try (ZipInputStream zipInputStream = new ZipInputStream(inputStream)) {
      ZipEntry zipEntry;

      while ((zipEntry = zipInputStream.getNextEntry()) != null) {
        if (!StringUtils.equals(zipEntry.getName(), ASiCUtils.MIME_TYPE)) {
          continue; // Entry name is not "mimetype": skip
        }
        byte[] buffer = new byte[maxMimeTypeLength];
        // Read at most the number of bytes that is equal to the longest allowed mimetype
        int readLength = IOUtils.read(zipInputStream, buffer, 0, maxMimeTypeLength);
        if (readLength == maxMimeTypeLength && zipInputStream.read() >= 0) {
          return false; // Entry is longer than the longest allowed mimetype: return false
        }
        byte[] mimeTypeBytes = (readLength == maxMimeTypeLength) ? buffer : ArrayUtils
                .subarray(buffer, 0, readLength);
        return allowedMimeTypes.stream().anyMatch(mt -> Arrays.equals(mt, mimeTypeBytes));
      }
    }

    return false;
  }

  private ContainerUtils() {
  }

}
