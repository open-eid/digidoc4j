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

import eu.europa.esig.dss.spi.client.http.DataLoader;

import java.io.Serializable;

/**
 * Manages the creation of new data loaders. Data loaders are used in getting OCSP and TimeStamp requests and
 * downloading certificates from the Trusted List (TSL).
 */
public interface DataLoaderFactory extends Serializable {

  /**
   * Create a new data loader instance.
   *
   * @return new data loader.
   */
  DataLoader create();

}
