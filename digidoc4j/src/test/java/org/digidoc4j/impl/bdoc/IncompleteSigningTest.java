/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
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
import org.digidoc4j.exceptions.TslRefreshException;
import org.digidoc4j.test.MockConfigurableDataLoader;
import org.digidoc4j.test.MockConfigurableFileLoader;
import org.digidoc4j.test.MockTSLRefreshCallback;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.matchesRegex;
import static org.hamcrest.Matchers.startsWith;

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

  private static final String CERTIFICATE_VALIDATION_EXCEPTION_MESSAGE_REGEX = "OCSP response certificate <C-[A-F0-9]+> match is not found in TSL";
  private static final String CONTAINER_VALIDATION_ERROR_MESSAGE = "The certificate validation is not conclusive!";
  private static final String OCSP_REQUEST_FAILED_EXCEPTION_MESSAGE_PART = "OCSP request failed";
  private static final String TECHNICAL_EXCEPTION_TSP_MESSAGE_PART = "Got error in signing process: Failed to POST URL: http://demo.sk.ee/tsa";
  private static final String TSL_REFRESH_EXCEPTION_MESSAGE_PART = "Failed to download LoTL";

  @Test
  public void signatureProfileLtShouldFailWhenSigningCertificateIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    Container container = createNonEmptyContainerByConfiguration();

    OCSPRequestFailedException caughtException = assertThrows(
            OCSPRequestFailedException.class,
            () -> createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(OCSP_REQUEST_FAILED_EXCEPTION_MESSAGE_PART));
  }

  @Test
  public void signatureProfileLtaShouldFailWhenSigningCertificateIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    Container container = createNonEmptyContainerByConfiguration();

    OCSPRequestFailedException caughtException = assertThrows(
            OCSPRequestFailedException.class,
            () -> createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(OCSP_REQUEST_FAILED_EXCEPTION_MESSAGE_PART));
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenSigningCertificateIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    Container container = createNonEmptyContainerByConfiguration();

    Signature signature = createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);

    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    TestAssert.assertContainsErrors(validationResult.getErrors(), CONTAINER_VALIDATION_ERROR_MESSAGE);
  }

  @Test
  public void signatureProfileLtShouldFailWhenOcspResponderIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    ensureCertificateTrustedByTSL(pkcs12SignatureToken.getCertificate());
    Container container = createNonEmptyContainerByConfiguration();

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), matchesRegex(CERTIFICATE_VALIDATION_EXCEPTION_MESSAGE_REGEX));
  }

  @Test
  public void signatureProfileLtaShouldFailWhenOcspResponderIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    ensureCertificateTrustedByTSL(pkcs12SignatureToken.getCertificate());
    Container container = createNonEmptyContainerByConfiguration();

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), matchesRegex(CERTIFICATE_VALIDATION_EXCEPTION_MESSAGE_REGEX));
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenOcspResponderIsNotTrustedByTSL() {
    setUpProdConfigurationWithTestTsaAndOcsp();
    ensureCertificateTrustedByTSL(pkcs12SignatureToken.getCertificate());
    Container container = createNonEmptyContainerByConfiguration();

    Signature signature = createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);

    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    TestAssert.assertContainsErrors(validationResult.getErrors(), CONTAINER_VALIDATION_ERROR_MESSAGE);
  }

  @Test
  public void signatureProfileLtShouldFailWhenTslCouldNotBeLoadedWithDefaultTslCallback() {
    setUpTestConfigurationWithEmptyTSL();
    Container container = createNonEmptyContainerByConfiguration();

    TslRefreshException caughtException = assertThrows(
            TslRefreshException.class,
            () -> createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), startsWith(TSL_REFRESH_EXCEPTION_MESSAGE_PART));
  }

  @Test
  public void signatureProfileLtShouldFailWhenTslCouldNotBeLoadedWithCustomTslCallback() {
    setUpTestConfigurationWithEmptyTSL();
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    Container container = createNonEmptyContainerByConfiguration();

    OCSPRequestFailedException caughtException = assertThrows(
            OCSPRequestFailedException.class,
            () -> createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(OCSP_REQUEST_FAILED_EXCEPTION_MESSAGE_PART));
  }

  @Test
  public void signatureProfileLtaShouldFailWhenTslCouldNotBeLoadedWithDefaultTslCallback() {
    setUpTestConfigurationWithEmptyTSL();
    Container container = createNonEmptyContainerByConfiguration();

    TslRefreshException caughtException = assertThrows(
            TslRefreshException.class,
            () -> createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), startsWith(TSL_REFRESH_EXCEPTION_MESSAGE_PART));
  }

  @Test
  public void signatureProfileLtaShouldFailWhenTslCouldNotBeLoadedWithCustomTslCallback() {
    setUpTestConfigurationWithEmptyTSL();
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    Container container = createNonEmptyContainerByConfiguration();

    OCSPRequestFailedException caughtException = assertThrows(
            OCSPRequestFailedException.class,
            () -> createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(OCSP_REQUEST_FAILED_EXCEPTION_MESSAGE_PART));
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenTslCouldNotBeLoaded() {
    setUpTestConfigurationWithEmptyTSL();
    Container container = createNonEmptyContainerByConfiguration();

    Signature signature = createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);

    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    TestAssert.assertContainsErrors(validationResult.getErrors(), CONTAINER_VALIDATION_ERROR_MESSAGE);
  }

  @Test
  public void signatureProfileLtShouldFailWhenTslLoadingFails() {
    setUpTestConfigurationWithFailingTSL();
    Container container = createNonEmptyContainerByConfiguration();

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(TECHNICAL_EXCEPTION_TSP_MESSAGE_PART));
  }

  @Test
  public void signatureProfileLtaShouldFailWhenTslLoadingFails() {
    setUpTestConfigurationWithFailingTSL();
    Container container = createNonEmptyContainerByConfiguration();

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(TECHNICAL_EXCEPTION_TSP_MESSAGE_PART));
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenTslLoadingFails() {
    setUpTestConfigurationWithFailingTSL();
    Container container = createNonEmptyContainerByConfiguration();

    Signature signature = createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);

    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    TestAssert.assertContainsErrors(validationResult.getErrors(), CONTAINER_VALIDATION_ERROR_MESSAGE);
  }

  @Test
  public void signatureProfileLtShouldFailWhenDataLoadersFail() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    Container container = createNonEmptyContainerByConfiguration();

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(TECHNICAL_EXCEPTION_TSP_MESSAGE_PART));
  }

  @Test
  public void signatureProfileLtaShouldFailWhenDataLoadersFail() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    Container container = createNonEmptyContainerByConfiguration();

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(TECHNICAL_EXCEPTION_TSP_MESSAGE_PART));
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenDataLoadersFail() {
    setUpTestConfigurationWithOkTslButFailingDataLoaders();
    Container container = createNonEmptyContainerByConfiguration();

    Signature signature = createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);

    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    TestAssert.assertContainsErrors(validationResult.getErrors(), CONTAINER_VALIDATION_ERROR_MESSAGE);
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
              String message = String.format("Failed to POST URL: %s; content: %s", url, contentHex);
              throw new DSSException(message);
            });

    DSSFileLoader failingFileLoader = new MockConfigurableFileLoader()
            .withDocumentGetter(url -> {
              String message = String.format("Failed to GET URL: %s", url);
              throw new DSSException(message);
            });

    configuration.setOcspDataLoaderFactory(() -> failingDataLoader);
    configuration.setTslFileLoaderFactory(() -> failingFileLoader);
    configuration.setTspDataLoaderFactory(() -> failingDataLoader);
  }

}
