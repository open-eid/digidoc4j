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

import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;

import java.io.Serializable;

/**
 * Manages the creation of new OCSP sources.
 */
@FunctionalInterface
public interface OCSPSourceFactory extends Serializable {

  /**
   * Create a new OCSP source instance.
   *
   * @return new OCSP source.
   */
  OCSPSource create();

}
