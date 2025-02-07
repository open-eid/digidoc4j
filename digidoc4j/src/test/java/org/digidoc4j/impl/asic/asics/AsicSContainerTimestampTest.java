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
import org.digidoc4j.impl.asic.cades.AsicContainerTimestampTest;
import org.digidoc4j.impl.asic.cades.CadesTimestamp;

public class AsicSContainerTimestampTest extends AsicContainerTimestampTest<AsicSContainerTimestamp> {

  @Override
  protected AsicSContainerTimestamp createDefaultAsicContainerTimestampWith(CadesTimestamp cadesTimestamp) {
    return new AsicSContainerTimestamp(cadesTimestamp);
  }

  @Override
  protected AsicSContainerTimestamp createDefaultAsicContainerTimestampWith(CadesTimestamp cadesTimestamp, AsicArchiveManifest archiveManifest) {
    return new AsicSContainerTimestamp(cadesTimestamp, archiveManifest);
  }

}
