package org.digidoc4j.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.MimeType;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class MimeTypeUtil {

  private static final Logger log = LoggerFactory.getLogger(MimeTypeUtil.class);

  private MimeTypeUtil() {
  }

  public static MimeType mimeTypeOf(String mimeType) {
    switch (mimeType) {
      case "txt.html":
        log.warn("Incorrect Mime-Type <{}> detected, fixing ...", mimeType);
        mimeType = "text/html";
        break;
    }
    if (mimeType.indexOf('\\') > 0) {
      log.warn("Incorrect Mime-Type <{}> detected, fixing ...", mimeType);
      mimeType = mimeType.replace("\\", "/");
    }
    return MimeType.fromMimeTypeString(mimeType);
  }

}
