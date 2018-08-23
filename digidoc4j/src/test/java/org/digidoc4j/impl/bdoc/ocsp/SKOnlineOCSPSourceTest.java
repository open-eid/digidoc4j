package org.digidoc4j.impl.bdoc.ocsp;

import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.test.util.TestSigningUtil;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import eu.europa.esig.dss.x509.CertificateToken;

@RunWith(MockitoJUnitRunner.class)
public class SKOnlineOCSPSourceTest extends AbstractTest {

  private X509Certificate issuerCert;

  @Mock
  private SkDataLoader dataLoader;

  @Test
  public void gettingOCSPToken_shouldReturnNull_whenOCSPResponseIsEmpty() throws Exception {
    Mockito.when(this.dataLoader.post(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(
        new byte[]{48, 3, 10, 1, 6});
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.defaultOCSPSource().withConfiguration(
        this.configuration).build();
    source.setDataLoader(this.dataLoader);
    Assert.assertNull(source.getOCSPToken(new CertificateToken(TestSigningUtil.SIGN_CERT),
        new CertificateToken(this.issuerCert)));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    Security.addProvider(new BouncyCastleProvider());
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.issuerCert = this.openX509Certificate(
        Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt")); //Any certificate will do
  }

}
