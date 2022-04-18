/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import eu.europa.esig.dss.spi.client.http.DSSFileLoader;

import java.io.Serializable;

/**
 * Manages the creation of new file loaders. File loaders are used for
 * downloading lists of trusted lists (LOTL) and trusted lists (TL).
 */
@FunctionalInterface
public interface DSSFileLoaderFactory extends Serializable {

  /**
   * Create a new file loader instance.
   *
   * @return new file loader.
   */
  DSSFileLoader create();

}
