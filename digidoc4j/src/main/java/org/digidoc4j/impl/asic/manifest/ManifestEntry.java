/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.manifest;

import java.io.Serializable;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Contains information of filenames and mimetypes.
 */
public final class ManifestEntry implements Serializable{
  private static final Logger logger = LoggerFactory.getLogger(ManifestEntry.class);
  private String fileName;
  private String mimeType;

  /**
   * ManifestEntry constructor
   *
   * @param fileName
   * @param mimeType
   */
  public ManifestEntry(String fileName, String mimeType) {
    this.fileName = fileName;
    this.mimeType = mimeType;
  }

  /**
   * Get the filename.
   *
   * @return filename
   */
  public String getFileName() {
    logger.debug("Filename: " + fileName);
    return fileName;
  }

  /**
   * Get the mimetype.
   *
   * @return mimetype
   */
  public String getMimeType() {
    logger.debug("Mime type: " + mimeType);
    return mimeType;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj instanceof ManifestEntry) {
      if (fileName.equals(((ManifestEntry)obj).getFileName())
          && mimeType.equals(((ManifestEntry)obj).getMimeType())) {
        return true;
      }
    }
    return false;
  }

  @Override
  public int hashCode() {
    return Objects.hash(fileName, mimeType);
  }
}
