package org.digidoc4j;

import java.nio.file.Paths;

import org.digidoc4j.exceptions.CertificateValidationException;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class CertificateValidatorBuilderTest extends AbstractTest {

  @Test
  public void testCertificateStatusGood() {
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/TESTofEECertificationCentreRootCA.crt"), this
        .configuration.getTSL());
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    validator.validate(
        this.openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt")));
  }

  @Test
  public void testCertificateStatusUntrusted() {
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    try {
      validator.validate(
          this.openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt")));
    } catch (CertificateValidationException e) {
      Assert.assertEquals("Not equals", CertificateValidationException.CertificateValidationStatus.UNTRUSTED, e
          .getCertificateStatus());
    }
  }

  @Test
  public void testCertificateStatusUnknown() {
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/TESTofEECertificationCentreRootCA.crt"), this
        .configuration.getTSL());
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    try {
      validator.validate(
          this.openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofStatusUnknown.cer")));
    } catch (CertificateValidationException e) {
      e.printStackTrace();
      Assert.assertEquals("Not equals", CertificateValidationException.CertificateValidationStatus.UNKNOWN, e
          .getCertificateStatus());
    }
  }

  @Test
  public void testCertificateSssstatusUntrusted() {
    this.addCertificateToTSL(Paths.get("src/test/resources/prodFiles/certs/ESTEID-SK2015.crt"), this
        .configuration.getTSL());
    this.addCertificateToTSL(Paths.get("src/test/resources/prodFiles/certs/test222.cer"), this
        .configuration.getTSL());
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    validator.validate(this.openX509Certificate(Paths.get("src/test/resources/prodFiles/certs/38207160020.cer")));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
