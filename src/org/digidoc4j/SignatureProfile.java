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

/**
 * Signature profile format.
 */
public enum SignatureProfile {
  /**
   * Time-mark, similar to LT.
   */
  LT_TM,
  /**
   * Time-stamp and OCSP confirmation
   */
  LT,
  /**
   * Archive timestamp, same as XAdES LTA (Long Term Archive time-stamp)
   */
  LTA,
  /**
   * no profile
   */
  B_BES
  //TODO: ADD later B_EPES, LTA_TM
}
