/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test.matcher;

import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.hamcrest.Matcher;

import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.equalTo;

public final class CommonMatchers {

  public static Matcher<List<String>> equalToSignatureUniqueIdList(Container container) {
    return equalToSignatureUniqueIdList(container.getSignatures());
  }

  public static Matcher<List<String>> equalToSignatureUniqueIdList(List<Signature> signatures) {
    return equalTo(signatures.stream().map(Signature::getUniqueId).collect(Collectors.toList()));
  }

  private CommonMatchers() {
  }

}
