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

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.utils.MimeTypeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ASIC container parser from input stream
 */
public class AsicStreamContainerParser extends AsicContainerParser{

  private static final Logger logger = LoggerFactory.getLogger(AsicStreamContainerParser.class);
  private ZipInputStream zipInputStream;

  /**
   * @param inputStream input stream
   * @param configuration configuration
   */
  public AsicStreamContainerParser(InputStream inputStream, Configuration configuration) {
    super(configuration);
    zipInputStream = new ZipInputStream(inputStream);
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
    return zipInputStream;
  }
}
