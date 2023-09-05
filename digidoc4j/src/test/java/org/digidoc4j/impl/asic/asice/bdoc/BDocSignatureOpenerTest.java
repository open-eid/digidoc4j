/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asice.bdoc;

import org.digidoc4j.Signature;
import org.digidoc4j.impl.asic.xades.AsicXadesSignatureOpener;
import org.digidoc4j.impl.asic.xades.AsicXadesSignatureOpenerTest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;

public class BDocSignatureOpenerTest extends AsicXadesSignatureOpenerTest {

  @Override
  protected AsicXadesSignatureOpener signatureOpener() {
    return new BDocSignatureOpener(configuration);
  }

  @Override
  protected void assertSignatureType(Signature signature) {
    assertThat(signature, instanceOf(BDocSignature.class));
  }

}
