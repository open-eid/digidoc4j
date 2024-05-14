/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.model.DSSDocument;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.impl.asic.cades.AsicContainerTimestamp;

/**
 * An implementation of timestamp token that covers the contents of ASiC-S containers.
 */
public class AsicSContainerTimestamp extends AsicContainerTimestamp {

  /**
   * Creates an ASiC-S timestamp token without ASiCArchiveManifest.
   *
   * @param timestampDocument timestamp document
   */
  public AsicSContainerTimestamp(DSSDocument timestampDocument) {
    super(timestampDocument, null);
  }

  /**
   * Creates an ASiC-S timestamp token with ASiCArchiveManifest.
   *
   * @param timestampDocument timestamp document
   * @param manifest ASiCArchiveManifest
   */
  public AsicSContainerTimestamp(DSSDocument timestampDocument, AsicArchiveManifest manifest) {
    super(timestampDocument, manifest);
  }

}
