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
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.apache.commons.lang3.tuple.Pair;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.test.util.TestZipUtil;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ContainerUtilsTest {

  @Test
  public void getMimeTypeStringFor_WhenContainerIsNull_ReturnsApplicationOctetStream() {
    String result = ContainerUtils.getMimeTypeStringFor(null);

    assertThat(result, equalTo("application/octet-stream"));
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsMock_ReturnsApplicationOctetStream() {
    Container mockedContainer = mock(Container.class);

    String result = ContainerUtils.getMimeTypeStringFor(mockedContainer);

    assertThat(result, equalTo("application/octet-stream"));
    verify(mockedContainer).getType();
    verifyNoMoreInteractions(mockedContainer);
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsAsice_ReturnsAsiceMimeTypeString() {
    Container asiceContainer = ContainerBuilder
            .aContainer(Container.DocumentType.ASICE)
            .build();

    String result = ContainerUtils.getMimeTypeStringFor(asiceContainer);

    assertThat(result, equalTo("application/vnd.etsi.asic-e+zip"));
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsAsics_ReturnsAsicsMimeTypeString() {
    Container asiceContainer = ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .build();

    String result = ContainerUtils.getMimeTypeStringFor(asiceContainer);

    assertThat(result, equalTo("application/vnd.etsi.asic-s+zip"));
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsBdoc_ReturnsAsiceMimeTypeString() {
    Container asiceContainer = ContainerBuilder
            .aContainer(Container.DocumentType.BDOC)
            .build();

    String result = ContainerUtils.getMimeTypeStringFor(asiceContainer);

    assertThat(result, equalTo("application/vnd.etsi.asic-e+zip"));
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsDdoc_ReturnsDdocMimeTypeString() {
    Container asiceContainer = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc");

    String result = ContainerUtils.getMimeTypeStringFor(asiceContainer);

    assertThat(result, equalTo("application/x-ddoc"));
  }

  @Test
  public void isAsicContainer_WhenNoAllowedMimeTypeStringsAreProvided_ThrowsException() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(new byte[0]);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> ContainerUtils.isAsicContainer(inputStreamSupplier)
    );

    assertThat(caughtException.getMessage(), equalTo("No allowed mimetype strings specified"));
  }

  @Test
  public void isAsicContainer_WhenInputIsEmpty_ReturnsFalse() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(new byte[0]);

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(false));
  }

  @Test
  public void isAsicContainer_WhenInputIsNotZipFile_ReturnsFalse() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier("Some text");

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(false));
  }

  @Test
  public void isAsicContainer_WhenInputIsNonAsicZipContainer_ReturnsFalse() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createDeflatedEntry("test.txt", "Some text.".getBytes(StandardCharsets.UTF_8))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(false));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithFirstStoredCustomAllowedMimeType_ReturnsTrue() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createStoredEntry(ASiCUtils.MIME_TYPE, "custom-mimetype".getBytes(StandardCharsets.UTF_8))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, "custom-mimetype");

    assertThat(result, equalTo(true));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithFirstStoredNonAsicMimeType_ReturnsFalse() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createStoredEntry(ASiCUtils.MIME_TYPE, "Some text.".getBytes(StandardCharsets.UTF_8))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(false));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithFirstStoredAsiceMimeType_ReturnsTrue() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createStoredEntry(ASiCUtils.MIME_TYPE, getMimeTypeBytes(MimeTypeEnum.ASICE))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(true));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithFirstStoredAsiceMimeTypeButAsiceIsNotAllowed_ReturnsFalse() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createStoredEntry(ASiCUtils.MIME_TYPE, getMimeTypeBytes(MimeTypeEnum.ASICE))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, MimeTypeEnum.ASICS.getMimeTypeString());

    assertThat(result, equalTo(false));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithFirstStoredAsicsMimeType_ReturnsTrue() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createStoredEntry(ASiCUtils.MIME_TYPE, getMimeTypeBytes(MimeTypeEnum.ASICS))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(true));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithFirstStoredAsicsMimeTypeButAsicsIsNotAllowed_ReturnsFalse() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createStoredEntry(ASiCUtils.MIME_TYPE, getMimeTypeBytes(MimeTypeEnum.ASICS))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, MimeTypeEnum.ASICE.getMimeTypeString());

    assertThat(result, equalTo(false));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithFirstDeflatedAsiceMimeType_ReturnsTrue() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createDeflatedEntry(ASiCUtils.MIME_TYPE, getMimeTypeBytes(MimeTypeEnum.ASICE))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(true));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithFirstDeflatedAsicsMimeType_ReturnsTrue() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createDeflatedEntry(ASiCUtils.MIME_TYPE, getMimeTypeBytes(MimeTypeEnum.ASICS))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(true));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithNonFirstDeflatedAsiceMimeType_ReturnsTrue() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createDeflatedEntry("test.txt", "Some text.\n".getBytes(StandardCharsets.UTF_8)),
            TestZipUtil.createDeflatedEntry(ASiCUtils.MIME_TYPE, getMimeTypeBytes(MimeTypeEnum.ASICE))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(true));
  }

  @Test
  public void isAsicContainer_WhenInputIsZipContainerWithNonFirstDeflatedAsicsMimeType_ReturnsTrue() {
    Supplier<InputStream> inputStreamSupplier = createInputStreamSupplier(
            TestZipUtil.createDeflatedEntry("test.txt", "Some text.\n".getBytes(StandardCharsets.UTF_8)),
            TestZipUtil.createDeflatedEntry(ASiCUtils.MIME_TYPE, getMimeTypeBytes(MimeTypeEnum.ASICS))
    );

    boolean result = ContainerUtils.isAsicContainer(inputStreamSupplier, getDefaultAsicMimeTypeStrings());

    assertThat(result, equalTo(true));
  }

  @SafeVarargs
  private static Supplier<InputStream> createInputStreamSupplier(Pair<ZipEntry, byte[]>... entries) {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try (ZipOutputStream zipOutputStream = new ZipOutputStream(byteArrayOutputStream)) {
      TestZipUtil.writeEntries(zipOutputStream, entries);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to write ZIP container", e);
    }
    return createInputStreamSupplier(byteArrayOutputStream.toByteArray());
  }

  private static Supplier<InputStream> createInputStreamSupplier(String utf8Text) {
    return createInputStreamSupplier(utf8Text.getBytes(StandardCharsets.UTF_8));
  }

  private static Supplier<InputStream> createInputStreamSupplier(byte[] bytes) {
    return () -> new ByteArrayInputStream(bytes);
  }

  private static String[] getMimeTypesAsStrings(MimeType... mimeTypes) {
    return Stream.of(mimeTypes).map(MimeType::getMimeTypeString).toArray(String[]::new);
  }

  private static String[] getDefaultAsicMimeTypeStrings() {
    return getMimeTypesAsStrings(MimeTypeEnum.ASICE, MimeTypeEnum.ASICS);
  }

  private static byte[] getMimeTypeBytes(MimeType mimeType) {
    return mimeType.getMimeTypeString().getBytes(StandardCharsets.UTF_8);
  }

}
