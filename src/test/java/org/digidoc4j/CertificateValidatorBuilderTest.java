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
      Assert.assertEquals("Not equals", CertificateValidationException.CertificateValidationStatus.UNKNOWN, e
          .getCertificateStatus());
    }
  }

  @Test
  public void testProductionCertificateStatusUntrustedWithWrongOCSPResponseVerificationCertificate() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/TESTofEECertificationCentreRootCA.crt"), this
        .configuration.getTSL());
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt"), this
        .configuration.getTSL());
    this.configuration.setOCSPResponseVerificationCertificatePath(
        "src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt");
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    try {
      validator.validate(
          this.openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofStatusUnknown.cer")));
    } catch (CertificateValidationException e) {
      Assert.assertEquals("Not equals", CertificateValidationException.CertificateValidationStatus.UNTRUSTED, e
          .getCertificateStatus());
    }
  }

  @Test
  public void testProductionCertificateStatusUnknownWithOCSPResponseVerificationCertificate() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/TESTofEECertificationCentreRootCA.crt"), this
        .configuration.getTSL());
    this.configuration.setOCSPResponseVerificationCertificatePath
        ("src/test/resources/prodFiles/certs/SK_OCSP_RESPONDER_2011.pem.cer");
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    try {
      validator.validate(
          this.openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt")));
    } catch (CertificateValidationException e) {
      Assert.assertEquals("Not equals", CertificateValidationException.CertificateValidationStatus.UNKNOWN, e
          .getCertificateStatus());
    }
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
