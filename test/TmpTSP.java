import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;

/**
 * Created by Andrei on 11.09.2017.
 */
public class TmpTSP {

  @Test
  public void conf(){
    Configuration configuration = new Configuration();
    configuration.loadConfiguration("testFiles/yaml-configurations/digidoc_test_conf_tsp_source.yaml");
    configuration.getTsps();
  }

  @Test
  public void signature(){
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.loadConfiguration("testFiles/yaml-configurations/digidoc_test_conf_tsp_source.yaml");
    configuration.getTsps();

    Container container = ContainerBuilder
        .aContainer()
        .withConfiguration(configuration)
        .build();

    container.addDataFile("testFiles/helper-files/test.txt", "text/plain");

    X509Certificate signerCert = getSignerCert();

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).
        withSignatureToken(new PKCS12SignatureToken("testFiles/p12/signout.p12", "test".toCharArray())).
        //withSigningCertificate(signerCert).
        invokeSigning();

    X509Cert cert = signature.getSigningCertificate();
    String subjectName = cert.getSubjectName(X509Cert.SubjectName.C);

    container.addSignature(signature);
    Assert.assertTrue(container.validate().isValid());
  }

  private static X509Certificate getSignerCert() {
    try {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      try (FileInputStream stream = new FileInputStream("testFiles/p12/signout.p12")) {
        keyStore.load(stream, "test".toCharArray());
      }
      return (X509Certificate) keyStore.getCertificate("1");
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading signer cert failed");
    }
  }

  @Test
  public void signatureLTTSA(){
    OnlineTSPSource tspSource = new OnlineTSPSource("http://demo.sk.ee/tsa/");
    tspSource.setPolicyOid("0.4.0.2023.1.1");
    tspSource.setDataLoader(new TimestampDataLoader()); // content-type is different

    byte[] digest = DSSUtils.digest(eu.europa.esig.dss.DigestAlgorithm.SHA512, "Hello world".getBytes());
    TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(eu.europa.esig.dss.DigestAlgorithm.SHA512, digest);
    Assert.assertNotNull(timeStampResponse);
  }
}
