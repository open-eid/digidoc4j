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

import eu.europa.esig.dss.spi.x509.aia.AIASource;

import java.io.Serializable;

/**
 * Manages the creation of new AIA sources.
 * AIA sources are used for resolving issuer certificates.
 */
@FunctionalInterface
public interface AIASourceFactory extends Serializable {

  /**
   * Create a new AIA source instance.
   *
   * @return new AIA source.
   */
  AIASource create();

}
