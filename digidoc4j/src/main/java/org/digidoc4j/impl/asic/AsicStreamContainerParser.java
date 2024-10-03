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

import eu.europa.esig.dss.enumerations.MimeType;
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

  private final CountingInputStream countingInputStream;
  private final ZipInputStream zipInputStream;
  private long totalContainerBytesUnpacked;

  /**
   * @param inputStream   input stream
   * @param configuration configuration
   */
  public AsicStreamContainerParser(InputStream inputStream, Configuration configuration) {
    super(configuration);
    countingInputStream = new CountingInputStream(inputStream);
    zipInputStream = new ZipInputStream(countingInputStream);
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
      totalContainerBytesUnpacked = 0L;
      while ((entry = zipInputStream.getNextEntry()) != null) {
        parseEntry(entry);
      }
    } catch (IOException e) {
      logger.error("Error reading asic container stream: " + e.getMessage());
      throw new TechnicalException("Error reading asic container stream", e);
    } finally {
      IOUtils.closeQuietly(zipInputStream);
    }
  }

  private void updateDataFilesMimeType() {
    for (DataFile dataFile : getDataFiles().values()) {
      String fileName = dataFile.getName();
      MimeType mimeType = MimeTypeUtil.mimeTypeOf(getDataFileMimeType(fileName));
      dataFile.getDocument().setMimeType(mimeType);
    }
  }

  @Override
  protected void extractManifest(ZipEntry entry) {
    AsicEntry asicEntry = extractAsicEntry(entry);
    parseManifestEntry(asicEntry.getContent());
  }

  @Override
  protected InputStream getZipEntryInputStream(ZipEntry entry) {
    return new ZipEntryInputStream(zipInputStream, this::validate);
  }

  private void validate(long bytesRead) {
    long totalCompressedBytesRead = countingInputStream.getByteCount();
    totalContainerBytesUnpacked += bytesRead;
    verifyContainerUnpackingIsSafeToProceed(totalCompressedBytesRead, totalContainerBytesUnpacked);
  }

}
