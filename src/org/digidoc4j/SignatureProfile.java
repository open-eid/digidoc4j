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
