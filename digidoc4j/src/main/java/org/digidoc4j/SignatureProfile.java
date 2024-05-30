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
   * Time-mark, similar to LT (BDoc 2.1 format).
   */
  LT_TM,
  /**
   * Signature with Long Term Data - Timestamp and OCSP confirmation (ASIC-E format)
   */
  LT,
  /**
   * Archive timestamp, same as XAdES LTA (Long Term Archive time-stamp)
   */
  LTA,
  /**
   * Signature with a timestamp - Timestamp without OCSP confirmation
   */
  T,
  /**
   * no profile (baseline)
   */
  B_BES,

  /**
   * no profile (baseline) with signature id (compatible with BDoc)
   */
  B_EPES;

  //TODO: ADD later LTA_TM

  /**
   * Find SignatureProfile by profile string.
   *
   * @param profile
   * @return SignatureProfile.
   */
  public static SignatureProfile findByProfile(String profile) {
    for (SignatureProfile signatureProfile : values()) {
      if (signatureProfile.name().equals(profile)) {
        return signatureProfile;
      }
    }
    return null;
  }
}
