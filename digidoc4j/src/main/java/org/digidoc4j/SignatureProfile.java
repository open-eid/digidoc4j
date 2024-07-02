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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Signature profile format.
 */
public enum SignatureProfile {
  /**
   * Time-mark, similar to LT (BDoc 2.1 format).
   */
  LT_TM(-1),
  /**
   * no profile (baseline) with signature id (compatible with BDoc)
   */
  B_EPES(-1),
  /**
   * no profile (baseline)
   */
  B_BES(1),
  /**
   * Signature with a timestamp - Timestamp without OCSP confirmation
   */
  T(2),
  /**
   * Signature with Long Term Data - Timestamp and OCSP confirmation (ASIC-E format)
   */
  LT(3),
  /**
   * Archive timestamp, same as XAdES LTA (Long Term Archive time-stamp)
   */
  LTA(4);

  //TODO: ADD later LTA_TM

  SignatureProfile(int extensionOrder) {
    this.extensionOrder = extensionOrder;
  }

  private final int extensionOrder;

  public int getExtensionOrder() {
    return extensionOrder;
  }

  public List<SignatureProfile> getExtensionOrder(SignatureProfile target) {
    if (this.extensionOrder < 0) {
      throw new IllegalArgumentException(String.format("Not allowed to extend from profile %s", this));
    }
    if (target.extensionOrder < 0) {
      throw new IllegalArgumentException(String.format("Not allowed to extend to profile %s", target));
    }
    if (target.extensionOrder < this.extensionOrder) {
      throw new IllegalArgumentException(String.format("Not allowed to extend from %s to %s", this, target));
    }
    if (target.extensionOrder == this.extensionOrder) {
        return Collections.singletonList(target);
    }
    return calculateExtensionOrder(target);
  }

  private List<SignatureProfile> calculateExtensionOrder(SignatureProfile target) {
    List<SignatureProfile> profilesInExtensionOrder = new ArrayList<>();

    SignatureProfile sp = this;
    do {
      sp = getNextProfileByExtensionOrder(sp);
      profilesInExtensionOrder.add(sp);
    } while (sp != target);

    return profilesInExtensionOrder;
  }

  private SignatureProfile getNextProfileByExtensionOrder(SignatureProfile profile) {
    return Arrays.stream(values())
            .filter(v -> v.extensionOrder == profile.extensionOrder + 1)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException(
                    String.format("Unable to find higher profile than %s", profile)
            ));
  }

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
