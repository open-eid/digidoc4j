/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.bdoc.ocsp.BDocTSOcspSource;
import org.junit.Test;

public class BDocTSOcspSourceTest {

  @Test
  public void gettingOcspNonce() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    BDocTSOcspSource ocspSource = new BDocTSOcspSource(configuration);
    Extension nonce = ocspSource.createNonce();
    assertFalse(nonce.isCritical());
    assertEquals(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, nonce.getExtnId());
    assertTrue(nonce.getExtnValue().toString().length() > 0);
  }
}
