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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;

import java.util.Optional;

/**
 * Common container utilities.
 */
public final class ContainerUtils {

  public static final String DDOC_MIMETYPE_STRING = "application/x-ddoc";

  /**
   * Returns the preferred mimetype string for the specified container, or {@code application/octet-stream} if no better
   * match is found.
   *
   * @param container container to get mimetype for
   * @return preferred mimetype string for the specified container, or {@code application/octet-stream}
   */
  public static String getMimeTypeStringFor(Container container) {
    return Optional
            .ofNullable(container)
            .map(Container::getType)
            .map(ContainerUtils::mapContainerTypeToMimeTypeString)
            .orElseGet(MimeTypeEnum.BINARY::getMimeTypeString);
  }

  private static String mapContainerTypeToMimeTypeString(String containerType) {
    switch (containerType) {
      case Constant.ASICE_CONTAINER_TYPE:
      case Constant.BDOC_CONTAINER_TYPE:
        return MimeTypeEnum.ASICE.getMimeTypeString();
      case Constant.ASICS_CONTAINER_TYPE:
        return MimeTypeEnum.ASICS.getMimeTypeString();
      case Constant.DDOC_CONTAINER_TYPE:
        return DDOC_MIMETYPE_STRING;
      default:
        return null;
    }
  }

  private ContainerUtils() {
  }

}
