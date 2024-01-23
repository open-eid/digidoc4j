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

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class MimeTypeUtil {

  private static final Logger log = LoggerFactory.getLogger(MimeTypeUtil.class);

  private MimeTypeUtil() {
  }

  /**
   * When DD4J discovers mimeType which is in wrong format, then we try to fix it
   *
   * @param mimeType mime type
   * @return correct mime type
   */
  public static MimeType mimeTypeOf(String mimeType) {
    switch (mimeType) {
      case "txt.html":
        log.warn("Incorrect Mime-Type <{}> detected, fixing ...", mimeType);
        mimeType = "text/html";
        break;
      case "file":
        log.warn("Incorrect Mime-Type <{}> detected, fixing ...", mimeType);
        mimeType = "application/octet-stream";
        break;
    }
    if (mimeType.indexOf('\\') > 0) {
      log.warn("Incorrect Mime-Type <{}> detected, fixing ...", mimeType);
      mimeType = mimeType.replace("\\", "/");
    }
    return fromMimeTypeString(mimeType);
  }

  /**
   * Returns the first representation of the {@code MimeType} corresponding to the given mime-type string,
   * or a custom {@code MimeType} object with the specified mime-type string if no existing representation
   * of the {@code MimeType} is found.
   * Use this method when support for custom mime-types is needed.
   * In case fallback to {@link eu.europa.esig.dss.enumerations.MimeTypeEnum#BINARY} is preferred for non-standard
   * mime-types, use {@link MimeType#fromMimeTypeString(String)}.
   *
   * @param mimeTypeString is a string identifier composed of two parts: a "type" and a "subtype"
   * @return the extrapolated mime-type from the {@code String}
   *
   * @see MimeType#fromMimeTypeString(String)
   */
  public static MimeType fromMimeTypeString(final String mimeTypeString) {
    Objects.requireNonNull(mimeTypeString, "The mimeTypeString cannot be null!");

    for (MimeTypeLoader mimeTypeLoader : ServiceLoader.load(MimeTypeLoader.class)) {
      MimeType mimeType = mimeTypeLoader.fromMimeTypeString(mimeTypeString);
      if (mimeType != null) {
        return mimeType;
      }
    }

    return new CustomMimeType(mimeTypeString);
  }

  static final class CustomMimeType implements MimeType {

    private final String mimeTypeString;

    CustomMimeType(final String mimeTypeString) {
      this.mimeTypeString = mimeTypeString;
    }

    @Override
    public String getMimeTypeString() {
      return mimeTypeString;
    }

    @Override
    public String getExtension() {
      return null;
    }

    @Override
    public int hashCode() {
      return mimeTypeString.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (obj instanceof CustomMimeType) {
        CustomMimeType other = (CustomMimeType) obj;
        return mimeTypeString.equals(other.mimeTypeString);
      } else {
        return false;
      }
    }

    @Override
    public String toString() {
      return "MimeType [mimeTypeString=" + mimeTypeString + "]";
    }

  }

}
