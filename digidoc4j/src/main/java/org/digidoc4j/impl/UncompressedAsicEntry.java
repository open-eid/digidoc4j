/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import org.digidoc4j.impl.asic.AsicEntry;

import java.util.function.Supplier;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;

/**
 * An {@link AsicEntry} that retains the required metadata needed for a {@link ZipEntry} using {@link ZipEntry#STORED}
 * compression method. If no such metadata is present in the original {@link ZipEntry} object, it can be applied via
 * {@link UncompressedAsicEntry#updateMetadataIfNotPresent(Supplier)} by providing the raw bytes of the content this
 * entry represents.
 */
public class UncompressedAsicEntry extends AsicEntry {

  private long crc;
  private long size;

  /**
   * @param zipEntry original {@link ZipEntry} object
   */
  public UncompressedAsicEntry(ZipEntry zipEntry) {
    super(zipEntry);
    crc = zipEntry.getCrc();
    size = zipEntry.getSize();
  }

  /**
   * Calculates the metadata, required to store this entry as a {@link ZipEntry} using the {@link ZipEntry#STORED}
   * compression method, based on the raw bytes provided by {@code contentBytesSupplier}, if this metadata is not
   * already present.
   *
   * @param contentBytesSupplier {@link Supplier} of the raw bytes of the content this {@link AsicEntry} represents
   */
  public void updateMetadataIfNotPresent(Supplier<byte[]> contentBytesSupplier) {
    if (isRequiredMetadataMissing()) {
      byte[] contentBytes = contentBytesSupplier.get();
      size = contentBytes.length;

      CRC32 crc32 = new CRC32();
      crc32.update(contentBytes);
      crc = crc32.getValue();
    }
  }

  /**
   * Create a {@link ZipEntry} representing this object.
   *
   * @return the {@link ZipEntry} representing this object
   * @throws IllegalStateException if any of the metadata required to store the {@link ZipEntry} using the
   * {@link ZipEntry#STORED} compression method is missing
   */
  @Override
  public ZipEntry getZipEntry() {
    if (isRequiredMetadataMissing()) {
      throw new IllegalStateException("Missing metadata required for using STORED compression method");
    }
    ZipEntry zipEntry = super.getZipEntry();
    zipEntry.setMethod(ZipEntry.STORED);
    zipEntry.setCompressedSize(size);
    zipEntry.setSize(size);
    zipEntry.setCrc(crc);
    return zipEntry;
  }

  private boolean isRequiredMetadataMissing() {
    return (crc == -1 || size == -1);
  }

}
