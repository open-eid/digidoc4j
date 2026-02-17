/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import org.digidoc4j.impl.asic.AsicEntry;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.function.Supplier;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UncompressedAsicEntryTest {

  private static final String MOCK_ENTRY_NAME = "entry-name";

  @Test
  void entryCreatesZipEntryWithValidMetadataIfProvidedInOriginal() {
    ZipEntry originalZipEntry = new ZipEntry(MOCK_ENTRY_NAME);
    originalZipEntry.setSize(123L);
    originalZipEntry.setCrc(2345L);

    AsicEntry asicEntry = new UncompressedAsicEntry(originalZipEntry);
    ZipEntry derivedZipEntry = asicEntry.getZipEntry();

    assertZipEntry(derivedZipEntry, 123L, 2345L);
  }

  @Test
  void entryFailsToCreateZipEntryIfSizeIsMissing() {
    ZipEntry originalZipEntry = new ZipEntry(MOCK_ENTRY_NAME);
    originalZipEntry.setCrc(2345L);

    AsicEntry asicEntry = new UncompressedAsicEntry(originalZipEntry);
    assertThrows(IllegalStateException.class, asicEntry::getZipEntry);
  }

  @Test
  void entryFailsToCreateZipEntryIfCrcIsMissing() {
    ZipEntry originalZipEntry = new ZipEntry(MOCK_ENTRY_NAME);
    originalZipEntry.setSize(123L);

    AsicEntry asicEntry = new UncompressedAsicEntry(originalZipEntry);
    assertThrows(IllegalStateException.class, asicEntry::getZipEntry);
  }

  @Test
  void updatingMetadataDoesNotFetchContentBytesNorOverrideMetadataIfPresent() {
    Supplier<byte[]> supplierMock = (Supplier<byte[]>) Mockito.mock(Supplier.class);
    ZipEntry originalZipEntry = new ZipEntry(MOCK_ENTRY_NAME);
    originalZipEntry.setSize(3L);
    originalZipEntry.setCrc(345L);

    UncompressedAsicEntry asicEntry = new UncompressedAsicEntry(originalZipEntry);
    asicEntry.updateMetadataIfNotPresent(supplierMock);
    ZipEntry derivedZipEntry = asicEntry.getZipEntry();

    assertZipEntry(derivedZipEntry, 3L, 345L);
    Mockito.verifyNoInteractions(supplierMock);
  }

  @Test
  void updatingMetadataFetchesContentBytesAndOverridesMetadataIfSizeIsMissing() {
    ZipEntry originalZipEntry = new ZipEntry(MOCK_ENTRY_NAME);
    originalZipEntry.setCrc(2345L);

    UncompressedAsicEntry asicEntry = new UncompressedAsicEntry(originalZipEntry);
    asicEntry.updateMetadataIfNotPresent(() -> new byte[] {0, 1, 2, 3});
    ZipEntry derivedZipEntry = asicEntry.getZipEntry();

    assertZipEntry(derivedZipEntry, 4L, 2344191507L);
  }

  @Test
  void updatingMetadataFetchesContentBytesAndOverridesMetadataIfCrcIsMissing() {
    ZipEntry originalZipEntry = new ZipEntry(MOCK_ENTRY_NAME);
    originalZipEntry.setSize(123L);

    UncompressedAsicEntry asicEntry = new UncompressedAsicEntry(originalZipEntry);
    asicEntry.updateMetadataIfNotPresent(() -> new byte[] {0, 1, 2, 3, 4});
    ZipEntry derivedZipEntry = asicEntry.getZipEntry();

    assertZipEntry(derivedZipEntry, 5L, 1364906956L);
  }

  @Test
  void updatingMetadataFetchesContentBytesAndOverridesMetadataIfSizeAndCrcIsMissing() {
    ZipEntry originalZipEntry = new ZipEntry(MOCK_ENTRY_NAME);

    UncompressedAsicEntry asicEntry = new UncompressedAsicEntry(originalZipEntry);
    asicEntry.updateMetadataIfNotPresent(() -> new byte[] {0, 1, 2, 3, 4, 5});
    ZipEntry derivedZipEntry = asicEntry.getZipEntry();

    assertZipEntry(derivedZipEntry, 6L, 820760394L);
  }

  @Test
  void zipEntryCreatedByValidEntryIsSerializable() throws Exception {
    final byte[] contentBytes = new byte[] {1, 2, 3, 4};
    ByteArrayOutputStream bout = new ByteArrayOutputStream();

    try (ZipOutputStream zout = new ZipOutputStream(bout)) {
      UncompressedAsicEntry asicEntry = new UncompressedAsicEntry(new ZipEntry(MOCK_ENTRY_NAME));
      asicEntry.updateMetadataIfNotPresent(() -> contentBytes);

      zout.putNextEntry(asicEntry.getZipEntry());
      zout.write(contentBytes);
      zout.closeEntry();

      zout.finish();
    }

    try (
          ByteArrayInputStream bin = new ByteArrayInputStream(bout.toByteArray());
          ZipInputStream zin = new ZipInputStream(bin)
    ) {
      ZipEntry entry = zin.getNextEntry();
      assertZipEntry(entry, contentBytes.length, 3057449933L);

      byte[] buffer = new byte[contentBytes.length];
      assertEquals(contentBytes.length, zin.read(buffer));
      assertArrayEquals(contentBytes, buffer);

      zin.closeEntry();
    }
  }

  private static void assertZipEntry(ZipEntry zipEntry, long expectedSize, long expectedCrc) {
    assertEquals(MOCK_ENTRY_NAME, zipEntry.getName());
    assertEquals(ZipEntry.STORED, zipEntry.getMethod());
    assertEquals(expectedSize, zipEntry.getCompressedSize());
    assertEquals(expectedSize, zipEntry.getSize());
    assertEquals(expectedCrc, zipEntry.getCrc());
  }

}
