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
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.InMemoryDocument;

/**
 * ASIC file container parser
 */
public class AsicFileContainerParser extends AsicContainerParser{

  private static final Logger logger = LoggerFactory.getLogger(AsicFileContainerParser.class);
  private ZipFile zipFile;

  /**
   * @param containerPath path
   * @param configuration configuration
   */
  public AsicFileContainerParser(String containerPath, Configuration configuration) {
    super(configuration);
    try {
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
        parseEntry(zipEntry);
      }
    } finally {
      IOUtils.closeQuietly(zipFile);
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
