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

import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;

import java.io.Serializable;

/**
 * A callback for ensuring the state of the TSL after a refresh.
 * The callback is encouraged to throw an exception, if the TSL is not usable,
 * in order to stop the processes early that triggered the TSL refresh.
 */
@FunctionalInterface
public interface TSLRefreshCallback extends Serializable {

  /**
   * Ensures the state of the TSL and either:<ul>
   *     <li>throws an appropriate exception if the TSL is not in a usable state
   *     and the process that triggered the TSL refresh may not continue</li>
   *     <li>returns {@code false}, if the process that triggered the TSL refresh may continue,
   *     but the time of the TSL refresh must not be updated - the TSL is marked as expired</li>
   *     <li>returns {@code true}, if the TSL is good and the time of the TSL refresh must be
   *     updated - the next automatic TSL refresh will not be triggered before the next expiration
   *     period is over (see {@link Configuration#setTslCacheExpirationTime(long)})</li>
   * </ul>
   *
   * @param summary the information about the state of the TSL
   *
   * @return {@code true} if the TSL refresh time must be updated, {@code false} otherwise
   */
  boolean ensureTSLState(TLValidationJobSummary summary);

}
