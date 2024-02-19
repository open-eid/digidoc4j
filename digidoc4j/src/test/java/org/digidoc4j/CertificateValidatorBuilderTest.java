/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import org.digidoc4j.exceptions.CertificateValidationException;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.junit.Ignore;
import org.junit.Test;

import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.Assert.assertThrows;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class CertificateValidatorBuilderTest extends AbstractTest {

  @Test
  public void validate_WhenCnOfIssuerCertificatesAreSame_OnlyOneIssuerIsFound() {
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    validator.getCertificateSource().addCertificate(openCertificateToken("src/test/resources/testFiles/certs/sameCN_first.crt"));
    validator.getCertificateSource().addCertificate(openCertificateToken("src/test/resources/testFiles/certs/sameCN_second.crt"));
    X509Certificate certificateToTest = openX509Certificate("src/test/resources/testFiles/certs/sameCN_first_child.crt");

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> validator.validate(certificateToTest)
    );

    assertThat(
            caughtException.getCertificateStatus(),
            equalTo(CertificateValidationException.CertificateValidationStatus.UNKNOWN)
    );
    assertThat(
            caughtException.getMessage(),
            equalTo("Certificate is unknown")
    );
  }

  @Test
  public void validate_WhenCertificateStatusIsGood_NothingIsThrown() {
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    validator.getCertificateSource().addCertificate(openCertificateToken("src/test/resources/testFiles/certs/TESTofEECertificationCentreRootCA.crt"));
    X509Certificate certificateToTest = openX509Certificate("src/test/resources/testFiles/certs/TEST_of_ESTEID-SK_2015.pem.crt");

    validator.validate(certificateToTest);
  }

  @Test
  @Ignore("DD4J-931")
  public void validate_WhenCertificateIsNotTrusted_ValidationExceptionWithUntrustedStatusIsThrown() {
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    X509Certificate certificateToTest = openX509Certificate("src/test/resources/testFiles/certs/TEST_of_ESTEID-SK_2015.pem.crt");

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> validator.validate(certificateToTest)
    );

    assertThat(
            caughtException.getCertificateStatus(),
            equalTo(CertificateValidationException.CertificateValidationStatus.UNTRUSTED)
    );
    assertThat(
            caughtException.getMessage(),
            equalTo("Failed to parse issuer certificate token. Not all intermediate certificates added into OCSP.")
    );
  }

  @Test
  public void validate_WhenCertificateIsRevoked_ValidationExceptionWithRevokedStatusIsThrown() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setPreferAiaOcsp(false);
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(configuration).build();
    validator.getCertificateSource().addCertificate(openCertificateToken("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt"));
    X509Certificate certificateToTest = openX509Certificate("src/test/resources/testFiles/certs/TESTofStatusRevoked.cer");

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> validator.validate(certificateToTest)
    );

    assertThat(
            caughtException.getCertificateStatus(),
            equalTo(CertificateValidationException.CertificateValidationStatus.REVOKED)
    );
    assertThat(
            caughtException.getMessage(),
            equalTo("Certificate status is revoked")
    );
  }

  @Test
  public void validate_WhenOcspResponderCertificateIsNotTrusted_ValidationExceptionWithUntrustedStatusIsThrown() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.setTSL(new TSLCertificateSourceImpl());
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    validator.getCertificateSource().addCertificate(openCertificateToken("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt"));
    X509Certificate certificateToTest = openX509Certificate("src/test/resources/testFiles/certs/TESTofStatusRevoked.cer");

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> validator.validate(certificateToTest)
    );

    assertThat(
            caughtException.getCertificateStatus(),
            equalTo(CertificateValidationException.CertificateValidationStatus.UNTRUSTED)
    );
    assertThat(
            caughtException.getMessage(),
            matchesPattern("OCSP response certificate <C-[0-9A-F]{64}> match is not found in TSL")
    );
  }

  @Test
  public void validate_WhenOcspResponseStatusIsUnknown_ValidationExceptionWithUnknownStatusIsThrown() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    CertificateValidator validator = new CertificateValidatorBuilder().withConfiguration(this.configuration).build();
    validator.getCertificateSource().addCertificate(openCertificateToken("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt"));
    X509Certificate certificateToTest = openX509Certificate("src/test/resources/testFiles/certs/TESTofStatusRevoked.cer");

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> validator.validate(certificateToTest)
    );

    assertThat(
            caughtException.getCertificateStatus(),
            equalTo(CertificateValidationException.CertificateValidationStatus.UNKNOWN)
    );
    assertThat(
            caughtException.getMessage(),
            equalTo("Certificate is unknown")
    );
  }

  @Test
  public void importFromPath_WhenLoadingCertificatesFromCustomLocation_SourceContainsExpectedNumberOfCertificates() {
    ExtendedCertificateSource source = CertificateValidatorBuilder.getDefaultCertificateSource();

    source.importFromPath(Paths.get("src/test/resources/testFiles/certs"));

    assertThat(source.getCertificates(), hasSize(13));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
