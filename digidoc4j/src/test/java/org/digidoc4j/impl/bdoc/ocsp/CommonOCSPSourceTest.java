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
import org.digidoc4j.impl.OcspDataLoaderFactory;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

public class CommonOCSPSourceTest extends AbstractTest {

  @Test
  public void gettingOCSPNonce() {
    CommonOCSPSource source = new CommonOCSPSource(configuration);
    Extension nonce = source.createNonce(null);
    assertFalse(nonce.isCritical());
    assertEquals(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, nonce.getExtnId());
    assertThat(nonce.getExtnValue().toString(), not(emptyString()));
  }

  @Test
  public void gettingOCSPNonceShouldReturnNull_inCaseOfOlderAiaOcsp() {
    configuration.setPreferAiaOcsp(true);
    CommonOCSPSource source = new CommonOCSPSource(configuration);
    source.setDataLoader(new OcspDataLoaderFactory(configuration).create());
    X509Certificate certificate = pkcs12EccSignatureToken.getCertificate();
    source.getAccessLocation(certificate);
    Extension nonce = source.createNonce(certificate);
    assertNull(nonce);
  }

  @Test
  public void gettingOCSPNonceShouldReturnNull_whenNonceUsageIsTurnedOffInConfiguration() {
    configuration.setUseOcspNonce(false);
    CommonOCSPSource source = new CommonOCSPSource(configuration);
    Extension nonce = source.createNonce(null);
    assertNull(nonce);
    configuration.setUseOcspNonce(true);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = new Configuration(Configuration.Mode.TEST);
  }

}
