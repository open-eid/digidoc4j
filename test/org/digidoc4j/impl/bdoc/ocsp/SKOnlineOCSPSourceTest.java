package org.digidoc4j.impl.bdoc.ocsp;

import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.bdoc.SkDataLoader;
import org.digidoc4j.utils.CertificatesForTests;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;


@RunWith(MockitoJUnitRunner.class)
public class SKOnlineOCSPSourceTest {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Mock
  SkDataLoader dataLoader;

  X509Certificate issuerCert;
  Configuration configuration = new Configuration(Configuration.Mode.TEST);

  @Before
  public void setUp() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    issuerCert = openX509Cert("testFiles/certs/Juur-SK.pem.crt"); //Any certificate will do
  }

  @Test
  public void gettingOCSPToken_shouldReturnNull_whenOCSPResponseIsEmpty() throws Exception {
    mockDataLoader();
    SKOnlineOCSPSource ocspSource = new BDocTSOcspSource(configuration);
    ocspSource.setDataLoader(dataLoader);
    CertificateToken certificateToken = new CertificateToken(CertificatesForTests.SIGN_CERT);
    OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken, new CertificateToken(issuerCert));
    assertNull(ocspToken);
  }

  private void mockDataLoader() {
    byte[] emptyOcspResponse = {48, 3, 10, 1, 6};
    when(dataLoader.post(anyString(), any(byte[].class))).thenReturn(emptyOcspResponse);
  }

  private X509Certificate openX509Cert(String path) throws CertificateException, IOException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    try (FileInputStream inStream = new FileInputStream(new File(path))) {
      return  (X509Certificate) certificateFactory.generateCertificate(inStream);
    }
  }
}
