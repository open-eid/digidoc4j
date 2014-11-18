package org.digidoc4j.impl;

import java.util.Objects;

/**
 * Contains information of filenames and mimetypes.
 */
public final class ManifestEntry {
  private String fileName;
  private String mimeType;

  ManifestEntry(String fileName, String mimeType) {
    this.fileName = fileName;
    this.mimeType = mimeType;
  }

  /**
   * Get the filename.
   *
   * @return filename
   */
  public String getFileName() {
    return fileName;
  }

  /**
   * Get the mimetype.
   *
   * @return mimetype
   */
  public String getMimeType() {
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
