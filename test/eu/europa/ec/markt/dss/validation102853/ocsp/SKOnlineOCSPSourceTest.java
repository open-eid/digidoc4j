package eu.europa.ec.markt.dss.validation102853.ocsp;

import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.digidoc4j.Configuration;
import org.digidoc4j.utils.CertificatesForTests;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;


@RunWith(MockitoJUnitRunner.class)
public class SKOnlineOCSPSourceTest {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Mock
  CertificatePool certificatePool;

  @Mock
  DataLoader dataLoader;

  Configuration configuration = new Configuration(Configuration.Mode.TEST);

  @Test
  public void gettingOCSPToken_shouldReturnNull_whenOCSPResponseIsEmpty() throws Exception {
    mockCertificatePool();
    mockDataLoader();
    SKOnlineOCSPSource ocspSource = new BDocTSOcspSource(configuration);
    ocspSource.setDataLoader(dataLoader);
    CertificateToken certificateToken = new CertificateToken(CertificatesForTests.SIGN_CERT);
    OCSPToken ocspToken = ocspSource.getOCSPToken(certificateToken, certificatePool);
    assertNull(ocspToken);
  }

  private void mockCertificatePool() {
    List<CertificateToken> issuerList = new ArrayList<>();
    issuerList.add(new CertificateToken(CertificatesForTests.SIGN_CERT));
    when(certificatePool.get(any(X500Principal.class))).thenReturn(issuerList);
  }

  private void mockDataLoader() {
    byte[] emptyOcspResponse = {48, 3, 10, 1, 6};
    when(dataLoader.post(anyString(), any(byte[].class))).thenReturn(emptyOcspResponse);
  }
}
