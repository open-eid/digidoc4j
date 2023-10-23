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
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.CertificateValidationException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.TslRefreshException;
import org.digidoc4j.test.MockConfigurableDataLoader;
import org.digidoc4j.test.MockConfigurableFileLoader;
import org.digidoc4j.test.MockTSLRefreshCallback;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.TestSignatureToken;
import org.digidoc4j.test.util.TestCertificateUtil;
import org.digidoc4j.test.util.TestKeyPairUtil;
import org.digidoc4j.test.util.TestOcspUtil;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.time.Instant;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.matchesRegex;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThrows;

/**
 * Description of tests by their suffix:
 * <p>
 * ...WhenSigningCertificateIsNotTrustedByTSL() - uses TEST configuration and custom signature token that is not trusted by TSL.
 * <p>
 * ...WhenOcspResponderIsNotTrustedByTSL() - uses TEST configuration and custom OCSP responder that is not trusted by TSL.
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

  @BeforeClass
  public static void setUpStatic() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void signatureProfileLtShouldFailWhenSigningCertificateIsNotTrustedByTSL() throws Exception {
    setUpTestConfiguration();
    setUpMockedOcspResponder(true);
    SignatureToken signatureToken = createCustomSignatureToken(false);
    Container container = createNonEmptyContainerByConfiguration();

    OCSPRequestFailedException caughtException = assertThrows(
            OCSPRequestFailedException.class,
            () -> createSignatureBy(container, SignatureProfile.LT, signatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(OCSP_REQUEST_FAILED_EXCEPTION_MESSAGE_PART));
  }

  @Test
  public void signatureProfileLtaShouldFailWhenSigningCertificateIsNotTrustedByTSL() throws Exception {
    setUpTestConfiguration();
    setUpMockedOcspResponder(true);
    SignatureToken signatureToken = createCustomSignatureToken(false);
    Container container = createNonEmptyContainerByConfiguration();

    OCSPRequestFailedException caughtException = assertThrows(
            OCSPRequestFailedException.class,
            () -> createSignatureBy(container, SignatureProfile.LTA, signatureToken)
    );

    assertThat(caughtException.getMessage(), containsString(OCSP_REQUEST_FAILED_EXCEPTION_MESSAGE_PART));
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenSigningCertificateIsNotTrustedByTSL() throws Exception {
    setUpTestConfiguration();
    SignatureToken signatureToken = createCustomSignatureToken(false);
    Container container = createNonEmptyContainerByConfiguration();

    Signature signature = createSignatureBy(container, SignatureProfile.B_BES, signatureToken);

    ValidationResult validationResult = reloadSignature(signature, Configuration.Mode.TEST).validateSignature();
    TestAssert.assertContainsErrors(validationResult.getErrors(),
            "The certificate chain for signature is not trusted, it does not contain a trust anchor.");
  }

  @Test
  public void signatureProfileLtShouldFailWhenOcspResponderIsNotTrustedByTSL() throws Exception {
    setUpTestConfiguration();
    setUpMockedOcspResponder(false);
    Container container = createNonEmptyContainerByConfiguration();

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), matchesRegex(CERTIFICATE_VALIDATION_EXCEPTION_MESSAGE_REGEX));
  }

  @Test
  public void signatureProfileLtaShouldFailWhenOcspResponderIsNotTrustedByTSL() throws Exception {
    setUpTestConfiguration();
    setUpMockedOcspResponder(false);
    Container container = createNonEmptyContainerByConfiguration();

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), matchesRegex(CERTIFICATE_VALIDATION_EXCEPTION_MESSAGE_REGEX));
  }

  @Test
  public void signatureProfileBbesShouldNotFailWhenOcspResponderIsNotTrustedByTSL() throws Exception {
    setUpTestConfiguration();
    setUpMockedOcspResponder(false);
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

  private void setUpTestConfiguration() {
    configuration = Configuration.of(Configuration.Mode.TEST);
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

  private void setUpMockedOcspResponder(boolean registerResponderInTSL) throws CertIOException {
    AsymmetricCipherKeyPair issuerKeyPair = TestKeyPairUtil.generateEcKeyPair("secp384r1");
    PrivateKey issuerPrivateKey = TestKeyPairUtil.toPrivateKey((ECPrivateKeyParameters) issuerKeyPair.getPrivate());
    PublicKey issuerPublicKey = TestKeyPairUtil.toPublicKey((ECPublicKeyParameters) issuerKeyPair.getPublic());

    ContentSigner certificateSigner = TestCertificateUtil.createCertificateSigner(issuerPrivateKey, "SHA512withECDSA");

    AsymmetricCipherKeyPair responderKeyPair = TestKeyPairUtil.generateEcKeyPair("secp384r1");
    PrivateKey responderPrivateKey = TestKeyPairUtil.toPrivateKey((ECPrivateKeyParameters) responderKeyPair.getPrivate());
    PublicKey responderPublicKey = TestKeyPairUtil.toPublicKey((ECPublicKeyParameters) responderKeyPair.getPublic());

    Instant notBefore = Instant.now();
    Instant notAfter = notBefore.plusSeconds(3600L);
    X500Name issuerDn = new X500Name("CN=Custom OCSP responder issuer");
    X500Name responderDn = new X500Name("CN=Custom OCSP responder");

    X509CertificateHolder issuerCert = TestCertificateUtil.createX509v3CertificateBuilder(
            issuerDn, null, notBefore, notAfter, issuerDn, issuerPublicKey
    )
            .addExtension(TestCertificateUtil.createKeyUsageExtension(false, KeyUsage.keyCertSign))
            .addExtension(TestCertificateUtil.createIdPkixOcspNocheckExtension(false))
            .build(certificateSigner);

    X509CertificateHolder responderCert = TestCertificateUtil.createX509v3CertificateBuilder(
            issuerDn, null, notBefore, notAfter, responderDn, responderPublicKey
    )
            .addExtension(TestCertificateUtil.createExtendedKeyUsageExtension(false, KeyPurposeId.id_kp_OCSPSigning))
            .addExtension(TestCertificateUtil.createIdPkixOcspNocheckExtension(false))
            .build(certificateSigner);

    configuration.setOcspDataLoaderFactory(() -> new MockConfigurableDataLoader().withPoster((url, content) -> {
      OCSPReq ocspReq = TestOcspUtil.parseOcspRequest(content);
      BasicOCSPRespBuilder basicOCSPRespBuilder = TestOcspUtil.createBasicOCSPRespBuilder(responderCert);
      Optional
              .ofNullable(ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce))
              .map(Extensions::new)
              .ifPresent(basicOCSPRespBuilder::setResponseExtensions);
      for (Req req : ocspReq.getRequestList()) {
        basicOCSPRespBuilder.addResponse(req.getCertID(), org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
      }
      ContentSigner ocspSigner = TestOcspUtil.createOcspSigner(responderPrivateKey, "SHA512withECDSA");
      BasicOCSPResp basicOCSPResp = TestOcspUtil.buildBasicOCSPResp(basicOCSPRespBuilder, ocspSigner, responderCert);
      return TestOcspUtil.getOcspResponseBytes(TestOcspUtil.buildSuccessfulOCSPResp(basicOCSPResp));
    }));

    if (registerResponderInTSL) {
      configuration.getTSL().addTSLCertificate(TestCertificateUtil.toX509Certificate(issuerCert));
    }
  }

  private SignatureToken createCustomSignatureToken(boolean registerSignerInTSL) throws CertIOException {
    AsymmetricCipherKeyPair issuerKeyPair = TestKeyPairUtil.generateEcKeyPair("secp384r1");
    PrivateKey issuerPrivateKey = TestKeyPairUtil.toPrivateKey((ECPrivateKeyParameters) issuerKeyPair.getPrivate());
    PublicKey issuerPublicKey = TestKeyPairUtil.toPublicKey((ECPublicKeyParameters) issuerKeyPair.getPublic());

    ContentSigner certificateSigner = TestCertificateUtil.createCertificateSigner(issuerPrivateKey, "SHA512withECDSA");

    AsymmetricCipherKeyPair signerKeyPair = TestKeyPairUtil.generateEcKeyPair("secp384r1");
    PrivateKey signerPrivateKey = TestKeyPairUtil.toPrivateKey((ECPrivateKeyParameters) signerKeyPair.getPrivate());
    PublicKey signerPublicKey = TestKeyPairUtil.toPublicKey((ECPublicKeyParameters) signerKeyPair.getPublic());

    Instant notBefore = Instant.now();
    Instant notAfter = notBefore.plusSeconds(3600L);
    X500Name issuerDn = new X500Name("CN=Custom signer issuer");
    X500Name responderDn = new X500Name("CN=Custom signer");

    X509CertificateHolder issuerCert = TestCertificateUtil.createX509v3CertificateBuilder(
            issuerDn, null, notBefore, notAfter, issuerDn, issuerPublicKey
    )
            .addExtension(TestCertificateUtil.createKeyUsageExtension(false, KeyUsage.keyCertSign))
            .addExtension(TestCertificateUtil.createIdPkixOcspNocheckExtension(false))
            .build(certificateSigner);

    X509CertificateHolder signerCert = TestCertificateUtil.createX509v3CertificateBuilder(
            issuerDn, null, notBefore, notAfter, responderDn, signerPublicKey
    )
            .addExtension(TestCertificateUtil.createKeyUsageExtension(false, KeyUsage.digitalSignature))
            .build(certificateSigner);

    SignatureToken signatureToken = new TestSignatureToken(signerPrivateKey, signerCert);

    if (registerSignerInTSL) {
      configuration.getTSL().addTSLCertificate(TestCertificateUtil.toX509Certificate(issuerCert));
    }

    return signatureToken;
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
