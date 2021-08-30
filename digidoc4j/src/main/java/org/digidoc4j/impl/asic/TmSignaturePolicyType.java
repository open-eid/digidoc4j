/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import org.apache.commons.lang3.StringUtils;

import java.util.Objects;
import java.util.stream.Stream;

public enum TmSignaturePolicyType {

  BDOC_1_9_9("1.3.6.1.4.1.10015.1000.2.10.10"),
  BDOC_2_0_0("1.3.6.1.4.1.10015.1000.3.1.1"),
  BDOC_2_1_0("1.3.6.1.4.1.10015.1000.3.2.1"),
  BDOC_2_1_2("1.3.6.1.4.1.10015.1000.3.2.3"),
  ;

  private final String oid;

  TmSignaturePolicyType(String oid) {
    this.oid = Objects.requireNonNull(oid);
  }

  public String getOid() {
    return oid;
  }

  public static Stream<TmSignaturePolicyType> streamOfValues() {
    return Stream.of(TmSignaturePolicyType.values());
  }

  public static boolean isTmPolicyOid(String oid) {
    return streamOfValues().anyMatch(policy -> StringUtils.equals(policy.getOid(), oid));
  }

}
