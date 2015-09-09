/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.signers;

import eu.europa.ec.markt.dss.DSSUtils;
import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.Certificates;
import org.junit.Test;

import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;


public class ExternalSignerTest {

  @Test
  public void testGetCertificate() throws Exception {
    X509Certificate cert = DSSUtils.loadCertificate(Base64.decodeBase64(Certificates.SIGNING_CERTIFICATE)).getCertificate();

    ExternalSigner externalSigner = new ExternalSigner(cert) {
      @Override
      public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
        return new byte[0];
      }
    };
    byte[] certificateBytes = externalSigner.getCertificate().getEncoded();

    assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificateBytes));
  }

  @Test(expected = NotSupportedException.class)
  public void testGetPrivateKey() throws Exception {

    X509Certificate cert = DSSUtils.loadCertificate(Base64.decodeBase64(Certificates.SIGNING_CERTIFICATE)).getCertificate();

    ExternalSigner externalSigner = new ExternalSigner(cert) {
      @Override
      public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
        return new byte[0];
      }
    };

    externalSigner.getPrivateKey();
  }
}
