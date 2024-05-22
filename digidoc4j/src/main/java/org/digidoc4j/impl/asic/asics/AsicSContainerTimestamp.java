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

import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.impl.asic.cades.AsicContainerTimestamp;
import org.digidoc4j.impl.asic.cades.CadesTimestamp;

/**
 * An implementation of timestamp token that covers the contents of ASiC-S containers.
 */
public class AsicSContainerTimestamp extends AsicContainerTimestamp {

  /**
   * Creates an ASiC-S timestamp token without ASiCArchiveManifest.
   *
   * @param cadesTimestamp CAdES timestamp
   */
  public AsicSContainerTimestamp(CadesTimestamp cadesTimestamp) {
    super(cadesTimestamp, null);
  }

  /**
   * Creates an ASiC-S timestamp token with ASiCArchiveManifest.
   *
   * @param timestamp CAdES timestamp
   * @param manifest ASiCArchiveManifest
   */
  public AsicSContainerTimestamp(CadesTimestamp timestamp, AsicArchiveManifest manifest) {
    super(timestamp, manifest);
  }

}
