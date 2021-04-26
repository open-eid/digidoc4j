package org.digidoc4j.impl.bdoc;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.apache.commons.codec.binary.Hex;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.CertificateValidationException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.test.MockConfigurableDataLoader;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;


/**
 * Description of tests by their suffix:
 * <p>
 * ...WhenSigningCertificateIsNotTrustedByTSL() - uses PROD configuration in order to get a TSL where signing certificate is not trusted.
 * NB: TSP and OCSP sources are set to demo URLs in order to prevent requests to non-free services!
 * <p>
 * ...WhenOcspResponderIsNotTrustedByTSL() - uses PROD configuration in order to get a TSL where OCSP responder certificate is not trusted.
 * NB: TSP and OCSP sources are set to demo URLs in order to prevent requests to non-free TSA and get a non-trusted response from OCSP!
 * <p>
 * ...WhenTslCouldNotBeLoaded() - uses TEST configuration with empty SSL truststore in order to prevent TSL from loading.
 * <p>
 * ...WhenTslLoadingFails() - uses TEST configuration with failing data loaders in order to prevent TSL from loading.
 * <p>
 * ...WhenDataLoadersFail() - uses TEST configuration with successfully loaded TSL and subsequently configured failing
 * data loaders in order to make TSA and OCSP requests to fail.
 */
public class IncompleteSigningTest extends AbstractTest {

  private static final String LTV_VALIDATION_ERROR_MESSAGE = "The result of the LTV validation process is not acceptable to continue the process!";

  @Test(expected = OCSPRequestFailedException.class)
  public void signatureProfileLtTmShouldFailWhenSigningCertificateIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT_TM, pkcs12SignatureToken);
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signatureProfileLtShouldFailWhenSigningCertificateIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT, pkcs12SignatureToken);
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signatureProfileLtaShouldFailWhenSigningCertificateIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LTA, pkcs12SignatureToken);
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenSigningCertificateIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_BES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test
  public void signatureProfileBepesShouldNotFailWhenSigningCertificateIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_EPES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test(expected = CertificateValidationException.class)
  public void signatureProfileLtTmShouldFailWhenOcspResponderIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    ensureCertificateTrustedByTSL(pkcs12SignatureToken.getCertificate());
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT_TM, pkcs12SignatureToken);
  }

  @Test(expected = CertificateValidationException.class)
  public void signatureProfileLtShouldFailWhenOcspResponderIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    ensureCertificateTrustedByTSL(pkcs12SignatureToken.getCertificate());
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT, pkcs12SignatureToken);
  }

  @Test(expected = CertificateValidationException.class)
  public void signatureProfileLtaShouldFailWhenOcspResponderIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    ensureCertificateTrustedByTSL(pkcs12SignatureToken.getCertificate());
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LTA, pkcs12SignatureToken);
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenOcspResponderIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    ensureCertificateTrustedByTSL(pkcs12SignatureToken.getCertificate());
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_BES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test
  public void signatureProfileBepesShouldNotFailWheOcspResponderIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    ensureCertificateTrustedByTSL(pkcs12SignatureToken.getCertificate());
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_EPES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signatureProfileLtTmShouldFailWhenTslCouldNotBeLoaded() {
    setUpTestConfigurationWithEmptyTSL();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT_TM, pkcs12SignatureToken);
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signatureProfileLtShouldFailWhenTslCouldNotBeLoaded() {
    setUpTestConfigurationWithEmptyTSL();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT, pkcs12SignatureToken);
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signatureProfileLtaShouldFailWhenTslCouldNotBeLoaded() {
    setUpTestConfigurationWithEmptyTSL();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LTA, pkcs12SignatureToken);
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenTslCouldNotBeLoaded() {
    setUpTestConfigurationWithEmptyTSL();
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_BES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test
  public void signatureProfileBepesShouldNotFailWhenTslCouldNotBeLoaded() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_EPES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test(expected = TechnicalException.class)
  public void signatureProfileLtTmShouldFailWhenTslLoadingFails() {
    setUpTestConfigurationWithFailingTSL();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT_TM, pkcs12SignatureToken);
  }

  @Test(expected = TechnicalException.class)
  public void signatureProfileLtShouldFailWhenTslLoadingFails() {
    setUpTestConfigurationWithFailingTSL();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT, pkcs12SignatureToken);
  }

  @Test(expected = TechnicalException.class)
  public void signatureProfileLtaShouldFailWhenTslLoadingFails() {
    setUpTestConfigurationWithFailingTSL();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LTA, pkcs12SignatureToken);
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenTslLoadingFails() {
    setUpTestConfigurationWithFailingTSL();
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_BES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test
  public void signatureProfileBepesShouldNotFailWhenTslLoadingFails() {
    setUpTestConfigurationWithFailingTSL();
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_EPES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test(expected = TechnicalException.class)
  public void signatureProfileLtTmShouldFailWhenDataLoadersFail() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT_TM, pkcs12SignatureToken);
  }

  @Test(expected = TechnicalException.class)
  public void signatureProfileLtShouldFailWhenDataLoadersFail() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LT, pkcs12SignatureToken);
  }

  @Test(expected = TechnicalException.class)
  public void signatureProfileLtaShouldFailWhenDataLoadersFail() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.LTA, pkcs12SignatureToken);
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenDataLoadersFail() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_BES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  @Test
  public void signatureProfileBepesShouldNotFailWhenDataLoadersFail() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), SignatureProfile.B_EPES, pkcs12SignatureToken);
    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    Assert.assertTrue(
            "Validation result is expected to contain error: " + LTV_VALIDATION_ERROR_MESSAGE,
            validationResult.getErrors().stream().anyMatch(e -> e.getMessage().contains(LTV_VALIDATION_ERROR_MESSAGE))
    );
  }

  /**
   * Sets up PROD configuration in order to get TSL without OCSP responder and signer CA certificates.
   * NB: OCSP and TSP sources are set to demo URLs in order to prevent requests to non-free TSA and/or OCSP!
   */
  private void setUpProdConfigurationWithTestTsaAndOcsp() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    Configuration testConfiguration = Configuration.of(Configuration.Mode.TEST);
    configuration.setOcspSource(testConfiguration.getOcspSource());
    configuration.setTspSource(testConfiguration.getTspSource());
  }

  private void setUpTestConfigurationWithEmptyTSL() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setSslTruststorePath("classpath:testFiles/truststores/empty-truststore.p12");
    configuration.setSslTruststorePassword("digidoc4j-password");
    configuration.setSslTruststoreType("PKCS12");
    configuration.getTSL().invalidateCache();
  }

  private void setUpTestConfigurationWithFailingTSL() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configureFailingDataLoaders(configuration);
    configuration.getTSL().invalidateCache();
  }

  private void setUpTestConfigurationWithOkTslButFailingDataLoaders() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.getTSL().refresh();
    configureFailingDataLoaders(configuration);
  }

  private void ensureCertificateTrustedByTSL(X509Certificate certificate) {
    CertificateToken certificateToken = new CertificateToken(certificate);
    TSLCertificateSource certificateSource = configuration.getTSL();
    if (!certificateSource.getBySubject(certificateToken.getIssuer()).isEmpty()) {
      return;
    }
    addCertificateToTSL(
            Paths.get("src", "test", "resources", "testFiles", "certs", "TEST_of_ESTEID-SK_2015.pem.crt"),
            configuration.getTSL()
    );
    Assert.assertFalse("Issuer for '" + certificate.getSubjectDN().getName() + "' not found in TSL! Test or test files might be invalid or out-dated!",
            certificateSource.getBySubject(certificateToken.getIssuer()).isEmpty());
  }

  private Signature reloadSignature(Signature signature, Configuration.Mode mode) {
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      Container container = createNonEmptyContainerByConfiguration();
      container.addSignature(signature);
      container.save(out);
      out.flush();

      try (ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray())) {
        return ContainerOpener
                .open(in, Configuration.of(mode))
                .getSignatures().get(0);
      }
    } catch (IOException e) {
      throw new IllegalStateException("I/O operation failed", e);
    }
  }

  private static void configureFailingDataLoaders(Configuration configuration) {
    DataLoader failingDataLoader = new MockConfigurableDataLoader()
            .withGetter((url, refresh) -> {
              String message = String.format("Failed to GET URL: %s", url);
              if (refresh != null) {
                message += String.format("; refresh: %s", refresh);
              }
              throw new DSSException(message);
            })
            .withPoster((url, content) -> {
              String contentHex = (content == null) ? "null" : Hex.encodeHexString(content);
              throw new DSSException(String.format("Failed to POST URL: %s; content: %s", url, contentHex));
            });

    configuration.setOcspDataLoaderFactory(() -> failingDataLoader);
    configuration.setTslDataLoaderFactory(() -> failingDataLoader);
    configuration.setTspDataLoaderFactory(() -> failingDataLoader);
  }

}
