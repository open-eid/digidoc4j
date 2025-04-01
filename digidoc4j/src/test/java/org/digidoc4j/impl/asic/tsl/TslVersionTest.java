/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.tsl;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.Options;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.test.util.KeyStoreManager;
import org.digidoc4j.test.util.TestCertificateUtil;
import org.digidoc4j.test.util.TestKeyPairUtil;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainsExactSetOfErrors;
import static org.digidoc4j.test.util.TestTSLUtil.OTHER_TSL_CERTIFICATE_B64;
import static org.digidoc4j.test.util.TestTSLUtil.OTHER_TSL_LOCATION;
import static org.digidoc4j.test.util.TestTSLUtil.TSL_VERSION_IDENTIFIER;
import static org.digidoc4j.test.util.TestTSLUtil.loadTslFromTemplate;
import static org.digidoc4j.test.util.TestTSLUtil.signTslV5;
import static org.digidoc4j.test.util.TestTSLUtil.signTslV6;

public class TslVersionTest extends AbstractTest {

  private static final String TRUSTSTORE_PASSWORD = "pass";
  private static final String TRUSTSTORE_TYPE = "PKCS12";

  @Rule
  public WireMockRule instanceRule = new WireMockRule(Options.DYNAMIC_PORT);

  @BeforeClass
  public static void setUpStatic() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.getTSL().invalidateCache();
  }

  @After
  public void tearDown() {
    WireMock.reset();
  }

  @Test
  public void validateContainer_WhenTslV5IsLoadedButOnlyV6IsSupported_InvalidWithTrustedListErrors() {
    configuration.setValidationPolicy("src/test/resources/testFiles/constraints/eIDAS_test_constraint_version_6.xml");
    configureCustomTsl(
            "secp256r1",
            (signer, otherTlLocation) -> signTslV5(
                    loadTslFromTemplate(
                            new FileDocument("src/test/resources/testFiles/tsl/test-lotl-EE-4.xml.template"),
                            new HashMap<String, String>() {{
                              put(TSL_VERSION_IDENTIFIER, "5");
                              put(OTHER_TSL_CERTIFICATE_B64, encodeCertificateToBase64String(signer.getValue()));
                              put(OTHER_TSL_LOCATION, otherTlLocation);
                            }}
                    ),
                    signer
            ),
            (signer) -> signTslV5(
                    loadTslFromTemplate(
                            new FileDocument("src/test/resources/testFiles/tsl/test-tl-EE_T-30.xml.template"),
                            Collections.singletonMap(TSL_VERSION_IDENTIFIER, "5")
                    ),
                    signer
            ));
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice",
            configuration
    );

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsInvalid(validationResult);
    assertContainsExactSetOfErrors(validationResult.getErrors(),
            "No acceptable trusted lists has been found!",
            "The trusted list does not have the expected version!"
    );
  }

  @Test
  public void validateContainer_WhenTslV6IsLoadedButOnlyV5IsSupported_InvalidWithTrustedListErrors() {
    configuration.setValidationPolicy("src/test/resources/testFiles/constraints/eIDAS_test_constraint_version_5.xml");
    configureCustomTsl(
            "secp521r1",
            (signer, otherTlLocation) -> signTslV6(
                    loadTslFromTemplate(
                            new FileDocument("src/test/resources/testFiles/tsl/test-lotl-EE-4.xml.template"),
                            new HashMap<String, String>() {{
                              put(TSL_VERSION_IDENTIFIER, "6");
                              put(OTHER_TSL_CERTIFICATE_B64, encodeCertificateToBase64String(signer.getValue()));
                              put(OTHER_TSL_LOCATION, otherTlLocation);
                            }}
                    ),
                    signer
            ),
            (signer) -> signTslV6(
                    loadTslFromTemplate(
                            new FileDocument("src/test/resources/testFiles/tsl/test-tl-EE_T-30.xml.template"),
                            Collections.singletonMap(TSL_VERSION_IDENTIFIER, "6")
                    ),
                    signer
            ));
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice",
            configuration
    );

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsInvalid(validationResult);
    assertContainsExactSetOfErrors(validationResult.getErrors(),
            "No acceptable trusted lists has been found!",
            "The trusted list does not have the expected version!"
    );
  }

  @Test
  public void validateContainer_WhenTslV5IsLoadedUsingDefaultPolicy_Succeeds() {
    configureCustomTsl(
            "secp384r1",
            (signer, otherTlLocation) -> signTslV5(
                    loadTslFromTemplate(
                            new FileDocument("src/test/resources/testFiles/tsl/test-lotl-EE-4.xml.template"),
                            new HashMap<String, String>() {{
                              put(TSL_VERSION_IDENTIFIER, "5");
                              put(OTHER_TSL_CERTIFICATE_B64, encodeCertificateToBase64String(signer.getValue()));
                              put(OTHER_TSL_LOCATION, otherTlLocation);
                            }}
                    ),
                    signer
            ),
            (signer) -> signTslV5(
                    loadTslFromTemplate(
                            new FileDocument("src/test/resources/testFiles/tsl/test-tl-EE_T-30.xml.template"),
                            Collections.singletonMap(TSL_VERSION_IDENTIFIER, "5")
                    ),
                    signer
            ));
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice",
            configuration
    );

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsValid(validationResult);
  }

  @Test
  public void validateContainer_WhenTslV6IsLoadedUsingDefaultPolicy_Succeeds() {
    configureCustomTsl(
            "brainpoolP512r1",
            (signer, otherTlLocation) -> signTslV6(
                    loadTslFromTemplate(
                            new FileDocument("src/test/resources/testFiles/tsl/test-lotl-EE-4.xml.template"),
                            new HashMap<String, String>() {{
                              put(TSL_VERSION_IDENTIFIER, "6");
                              put(OTHER_TSL_CERTIFICATE_B64, encodeCertificateToBase64String(signer.getValue()));
                              put(OTHER_TSL_LOCATION, otherTlLocation);
                            }}
                    ),
                    signer
            ),
            (signer) -> signTslV6(
                    loadTslFromTemplate(
                            new FileDocument("src/test/resources/testFiles/tsl/test-tl-EE_T-30.xml.template"),
                            Collections.singletonMap(TSL_VERSION_IDENTIFIER, "6")
                    ),
                    signer
            ));
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice",
            configuration
    );

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsValid(validationResult);
  }

  private void configureCustomTsl(
          String tslSigningKeyEcCurveName,
          BiFunction<Pair<PrivateKey, CertificateToken>, String, DSSDocument> lotlGenerator,
          Function<Pair<PrivateKey, CertificateToken>, DSSDocument> tlGenerator
  ) {
    Pair<PrivateKey, CertificateToken> tslSigner = generateTslSigner(tslSigningKeyEcCurveName);

    String tlPath = "/tl-" + UUID.randomUUID() + ".xml";
    stubGetResponse(tlPath, DSSUtils.toByteArray(tlGenerator.apply(tslSigner)));

    String lotlPath = "/lotl-" + UUID.randomUUID() + ".xml";
    stubGetResponse(lotlPath, DSSUtils.toByteArray(lotlGenerator.apply(tslSigner, instanceRule.url(tlPath))));

    configuration.setLotlLocation(instanceRule.url(lotlPath));
    configuration.setLotlPivotSupportEnabled(false);
    configuration.setRequiredTerritories("EE_T");
    configuration.setTrustedTerritories("EE_T");

    File trustStoreFile = createTemporaryFileByExtension("p12");
    configuration.setLotlTruststorePath(trustStoreFile.getPath());
    configuration.setLotlTruststorePassword(TRUSTSTORE_PASSWORD);
    configuration.setLotlTruststoreType(TRUSTSTORE_TYPE);

    KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(TRUSTSTORE_PASSWORD.toCharArray());
    KeyStoreManager trustStore = new KeyStoreManager(TRUSTSTORE_TYPE, passwordProtection);
    trustStore.addTrustedCertificate(tslSigner.getValue().getCertificate());
    trustStore.save(trustStoreFile);
  }

  private void stubGetResponse(String path, byte[] responseBody) {
    instanceRule.stubFor(WireMock.get(path).willReturn(WireMock
            .aResponse().withStatus(200).withBody(responseBody)));
  }

  private static Pair<PrivateKey, CertificateToken> generateTslSigner(String ecCurveName) {
    AsymmetricCipherKeyPair keyPair = TestKeyPairUtil.generateEcKeyPair(ecCurveName);
    PrivateKey privateKey = TestKeyPairUtil.toPrivateKey((ECPrivateKeyParameters) keyPair.getPrivate());
    PublicKey publicKey = TestKeyPairUtil.toPublicKey((ECPublicKeyParameters) keyPair.getPublic());

    Instant notBefore = Instant.now();
    Instant notAfter = notBefore.plusSeconds(3600L);
    X500Name dnX500Name = new X500Name("CN=" + UUID.randomUUID());

    JcaX509v3CertificateBuilder certificateBuilder = TestCertificateUtil.createX509v3CertificateBuilder(
            dnX500Name, null, notBefore, notAfter, dnX500Name, publicKey
    );

    ContentSigner signer = TestCertificateUtil.createCertificateSigner(privateKey, "SHA512withECDSA");
    X509Certificate certificate = TestCertificateUtil.toX509Certificate(certificateBuilder.build(signer));

    return Pair.of(privateKey, new CertificateToken(certificate));
  }

  private static String encodeCertificateToBase64String(CertificateToken certificateToken) {
    return Base64.encodeBase64String(certificateToken.getEncoded());
  }

}
