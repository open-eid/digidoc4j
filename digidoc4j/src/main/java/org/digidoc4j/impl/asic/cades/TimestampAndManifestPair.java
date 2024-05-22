/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import java.io.Serializable;

/**
 * An interface representing a pair of a CAdES timestamp and an optional ASiCArchiveManifest.
 */
public interface TimestampAndManifestPair extends Serializable {

  /**
   * Returns an instance of {@link CadesTimestamp} associated with this entity.
   *
   * @return CAdES timestamp instance
   */
  CadesTimestamp getCadesTimestamp();

  /**
   * Returns an instance of {@link AsicArchiveManifest} associated with this entity, if present.
   *
   * @return ASiCArchiveManifest or {@code null}
   */
  AsicArchiveManifest getArchiveManifest();

}
