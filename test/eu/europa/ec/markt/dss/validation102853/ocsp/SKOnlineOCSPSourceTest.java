package eu.europa.ec.markt.dss.validation102853.ocsp;

import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

import org.digidoc4j.Configuration;
import org.digidoc4j.utils.CertificatesForTests;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;


@RunWith(MockitoJUnitRunner.class)
public class SKOnlineOCSPSourceTest {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Mock
  CertificateToken issuerCertificate;

  @Mock
  DataLoader dataLoader;
  Configuration configuration = new Configuration(Configuration.Mode.TEST);

  @Ignore("Test is missing bouncycastle dependency")
  @Test
  public void gettingOCSPToken_shouldReturnNull_whenOCSPResponseIsEmpty() throws Exception {
    mockDataLoader();
    SKOnlineOCSPSource ocspSource = new BDocTSOcspSource(configuration);
    ocspSource.setDataLoader(dataLoader);
    CertificateToken certificateToken = new CertificateToken(CertificatesForTests.SIGN_CERT);
    OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken, issuerCertificate);
    assertNull(ocspToken);
  }

  private void mockDataLoader() {
    byte[] emptyOcspResponse = {48, 3, 10, 1, 6};
    when(dataLoader.post(anyString(), any(byte[].class))).thenReturn(emptyOcspResponse);
  }
}
