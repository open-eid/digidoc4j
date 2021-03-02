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

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.CountingInputStream;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.utils.MimeTypeUtil;
import org.digidoc4j.utils.ZipEntryInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * ASIC container parser from input stream
 */
public class AsicStreamContainerParser extends AsicContainerParser {

  private static final Logger logger = LoggerFactory.getLogger(AsicStreamContainerParser.class);
  private ZipInputStream zipInputStream;
  private long entryOffset;
  private static final int BUFFER_SIZE = 512;
  CountingInputStream countingInputStream;

  /**
   * @param inputStream   input stream
   * @param configuration configuration
   */
  public AsicStreamContainerParser(InputStream inputStream, Configuration configuration) {
    super(configuration);
    this.countingInputStream = new CountingInputStream(inputStream);
    zipInputStream = new ZipInputStream(this.countingInputStream);
  }

  @Override
  protected void parseContainer() {
    parseZipStream();
    updateDataFilesMimeType();
  }

  private void parseZipStream() {
    logger.debug("Parsing zip stream");
    try {
      ZipEntry entry;

      while ((entry = zipInputStream.getNextEntry()) != null) {
        this.entryOffset = this.countingInputStream.getByteCount();
        parseEntry(entry);
      }
    } catch (IOException e) {
      logger.error("Error reading asic container stream: " + e.getMessage());
      throw new TechnicalException("Error reading asic container stream: ", e);
    } finally {
      IOUtils.closeQuietly(zipInputStream);
    }
  }

  private void updateDataFilesMimeType() {
    for (DataFile dataFile : getDataFiles().values()) {
      String fileName = dataFile.getName();
      String mimeType = MimeTypeUtil.mimeTypeOf(getDataFileMimeType(fileName)).getMimeTypeString();
      dataFile.setMediaType(mimeType);
    }
  }

  @Override
  protected void extractManifest(ZipEntry entry) {
    AsicEntry asicEntry = extractAsicEntry(entry);
    parseManifestEntry(asicEntry.getContent());
  }

  @Override
  protected InputStream getZipEntryInputStream(ZipEntry entry) {
    return new ZipEntryInputStream(zipInputStream, new EntryValidator()::validate);
  }

  protected class EntryValidator {
    public void validate(long unCompressed) throws IOException {
      long compressed = countingInputStream.getByteCount() - entryOffset;
      if (compressed < BUFFER_SIZE) {
        compressed = BUFFER_SIZE;
      }
      if (unCompressed > ZIP_ENTRY_THRESHOLD && compressed * ZIP_ENTRY_RATIO < unCompressed) {
        throw new IOException("Zip Bomb detected in the ZIP container. Validation is interrupted.");
      }
    }
  }

}
