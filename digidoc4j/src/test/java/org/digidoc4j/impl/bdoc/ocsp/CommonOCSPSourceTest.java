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

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.CommonOCSPSource;
import org.junit.Assert;
import org.junit.Test;

import java.security.cert.X509Certificate;

public class CommonOCSPSourceTest extends AbstractTest {

  @Test
  public void gettingOCSPNonce() throws Exception {
    CommonOCSPSource source = new CommonOCSPSource(this.configuration);
    Extension nonce = source.createNonce(null);
    Assert.assertFalse(nonce.isCritical());
    Assert.assertEquals(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, nonce.getExtnId());
    Assert.assertTrue(nonce.getExtnValue().toString().length() > 0);
  }

  @Test
  public void gettingOCSPNonceShouldReturnNull_inCaseOfOlderAiaOcsp() throws Exception {
    this.configuration.setPreferAiaOcsp(true);
    CommonOCSPSource source = new CommonOCSPSource(this.configuration);
    X509Certificate certificate = this.pkcs12EccSignatureToken.getCertificate();
    source.getAccessLocation(certificate);
    Extension nonce = source.createNonce(certificate);
    Assert.assertNull(nonce);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
