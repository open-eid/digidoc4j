package org.digidoc4j.impl.bdoc.ocsp;

import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.impl.asic.ocsp.BDocTSOcspSource;
import org.digidoc4j.impl.asic.ocsp.SKOnlineOCSPSource;
import org.digidoc4j.utils.CertificatesForTests;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

@RunWith(MockitoJUnitRunner.class)
public class SKOnlineOCSPSourceTest extends AbstractTest {

  private X509Certificate issuerCert;

  @Mock
  private SkDataLoader dataLoader;

  @Test
  public void gettingOCSPToken_shouldReturnNull_whenOCSPResponseIsEmpty() throws Exception {
    byte[] emptyOcspResponse = {48, 3, 10, 1, 6};
    Mockito.when(this.dataLoader.post(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(emptyOcspResponse);
    SKOnlineOCSPSource ocspSource = new BDocTSOcspSource(this.configuration);
    ocspSource.setDataLoader(this.dataLoader);
    CertificateToken certificateToken = new CertificateToken(CertificatesForTests.SIGN_CERT);
    OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken, new CertificateToken(this.issuerCert));
    Assert.assertNull(ocspToken);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    Security.addProvider(new BouncyCastleProvider());
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.issuerCert = this.openX509Certificate(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt")); //Any certificate will do
  }

}
