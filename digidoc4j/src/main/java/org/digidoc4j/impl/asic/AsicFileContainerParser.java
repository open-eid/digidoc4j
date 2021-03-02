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

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * ASIC file container parser
 */
public class AsicFileContainerParser extends AsicContainerParser {

  private static final Logger logger = LoggerFactory.getLogger(AsicFileContainerParser.class);
  private ZipFile zipFile;
  private long containerSize;

  /**
   * @param containerPath path
   * @param configuration configuration
   */
  public AsicFileContainerParser(String containerPath, Configuration configuration) {
    super(configuration);
    try {
      this.containerSize = DSSUtils.getFileByteSize(new FileDocument(containerPath));
      zipFile = new ZipFile(containerPath);
    } catch (IOException e) {
      logger.error("Error reading container from " + containerPath + " - " + e.getMessage());
      throw new RuntimeException("Error reading container from " + containerPath);
    }
  }

  @Override
  protected void parseContainer() {
    logger.debug("Parsing zip file");
    try {
      String zipFileComment = zipFile.getComment();
      setZipFileComment(zipFileComment);
      parseZipFileManifest();
      Enumeration<? extends ZipEntry> entries = zipFile.entries();
      while (entries.hasMoreElements()) {
        ZipEntry zipEntry = entries.nextElement();
        verifyIfZipBomb(getZipEntryInputStream(zipEntry));
        parseEntry(zipEntry);
      }
    } catch (IOException e) {
      throw new TechnicalException("Zip Bomb detected in the ZIP container. Validation is interrupted.");
    } finally {
      IOUtils.closeQuietly(zipFile);
    }
  }

  private void verifyIfZipBomb(InputStream inputStream) throws IOException {
    byte[] data = new byte[2048];
    int nRead;
    int byteCounter = 0;
    long allowedSize = containerSize * ZIP_ENTRY_RATIO;
    while ((nRead = inputStream.read(data)) != -1) {
      byteCounter += nRead;
      if (byteCounter > ZIP_ENTRY_THRESHOLD && byteCounter > allowedSize) {
        throw new TechnicalException("Zip Bomb detected in the ZIP container. Validation is interrupted.");
      }
    }
  }

  @Override
  protected void extractManifest(ZipEntry entry) {
    extractAsicEntry(entry);
  }

  @Override
  protected InputStream getZipEntryInputStream(ZipEntry entry) {
    try {
      return zipFile.getInputStream(entry);
    } catch (IOException e) {
      logger.error("Error reading data file '" + entry.getName() + "' from the asic container: " + e.getMessage());
      throw new TechnicalException("Error reading data file '" + entry.getName() + "' from the asic container", e);
    }
  }

  private void parseZipFileManifest() {
    ZipEntry entry = zipFile.getEntry(MANIFEST);
    if (entry == null) {
      return;
    }
    try {
      InputStream manifestStream = getZipEntryInputStream(entry);
      InMemoryDocument manifestFile = new InMemoryDocument(IOUtils.toByteArray(manifestStream));
      parseManifestEntry(manifestFile);
    } catch (IOException e) {
      logger.error("Error parsing manifest file: " + e.getMessage());
      throw new TechnicalException("Error parsing manifest file", e);
    }
  }
}
