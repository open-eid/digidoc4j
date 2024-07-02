/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import org.digidoc4j.SignatureProfile;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.T;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;

/**
 * Signature profile utils
 */
public final class ExtensionOrderUtils {

  private static final List<SignatureProfile> EXTENSION_ORDER = Arrays.asList(B_BES, T, LT, LTA);
  private static final EnumMap<SignatureProfile, Integer> EXTENSION_ORDER_LOOKUP =
          IntStream.range(0, EXTENSION_ORDER.size())
                  .boxed()
                  .collect(Collectors.toMap(
                          EXTENSION_ORDER::get,
                          i -> i,
                          (e1, e2) -> e1,
                          () -> new EnumMap<>(SignatureProfile.class)
                  ));

  private ExtensionOrderUtils() {
  }

  /**
   * Get a list of {@link SignatureProfile} enums for step-by-step signature extension.
   *
   * @param source a {@link SignatureProfile} from which the extension process is intended to be started
   * @param target a {@link SignatureProfile} to which extension process is intended to be done
   * @return a list of ordered {@link SignatureProfile} enums (incl. source and target profiles)
   */
  public static List<SignatureProfile> getExtensionOrder(SignatureProfile source, SignatureProfile target) {
    if (order(target) < order(source)) {
      throw new IllegalArgumentException(String.format("Not allowed to extend from %s to %s", source, target));
    }
    return EXTENSION_ORDER.stream()
            .filter(p -> order(p) >= order(source) && order(p) <= order(target))
            .collect(Collectors.toList());
  }

  private static int order(SignatureProfile profile) {
    if (!EXTENSION_ORDER_LOOKUP.containsKey(profile)) {
      throw new IllegalArgumentException(String.format("Extension not applicable for profile %s", profile));
    }
    return EXTENSION_ORDER_LOOKUP.get(profile);
  }
}
