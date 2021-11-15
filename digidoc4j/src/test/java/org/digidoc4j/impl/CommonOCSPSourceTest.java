package org.digidoc4j.impl;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.CertificateValidationException;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.digidoc4j.test.util.TestCertificateUtil;
import org.digidoc4j.test.util.TestKeyPairUtil;
import org.digidoc4j.test.util.TestOcspUtil;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

@RunWith(MockitoJUnitRunner.class)
public class CommonOCSPSourceTest extends AbstractTest {

  private static final String MOCK_OCSP_URL = "mock://issuer/ocsp";
  private static final AccessDescription OCSP_ACCESS_DESCRIPTION = TestCertificateUtil.createOcspUrlAccessDescription(MOCK_OCSP_URL);

  @Mock
  private Configuration configuration;
  @Mock
  private SkOCSPDataLoader ocspDataLoader;

  private TSLCertificateSourceImpl tslCertificateSource;

  @BeforeClass
  public static void setUpStatic() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  public void before() {
    tslCertificateSource = new TSLCertificateSourceImpl();
    Mockito.doReturn(tslCertificateSource).when(configuration).getTSL();
  }

  @Test
  public void getRevocationToken_ocspRespondsWithTrustedOcspCertificate_1elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(1);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[0]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificate_1elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(1);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1])
    );

    Assert.assertEquals(CertificateValidationException.CertificateValidationStatus.UNTRUSTED, caughtException.getCertificateStatus());
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificate_2elementOcspChain_ocspRootInTSL() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(2);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[1]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()[0]));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificate_2elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(2);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()[0]));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1])
    );

    Assert.assertEquals(CertificateValidationException.CertificateValidationStatus.UNTRUSTED, caughtException.getCertificateStatus());
  }

  @Test
  public void getRevocationToken_ocspRespondsWithTrustedOcspCertificateAndUntrustedOcspRoot_2elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(2);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[0]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificateAndTrustedOcspRoot_2elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(2);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[1]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificateAndUntrustedOcspRoot_2elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(2);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1])
    );

    Assert.assertEquals(CertificateValidationException.CertificateValidationStatus.UNTRUSTED, caughtException.getCertificateStatus());
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificateAndTrustedOcspIntermediate_3elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(3);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[1]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates,
            ocspKeyAndCertificates.getValue()[0], ocspKeyAndCertificates.getValue()[1]));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificateAndUntrustedOcspIntermediate_3elementOcspChain_ocspRootInTSL() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(3);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[2]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates,
            ocspKeyAndCertificates.getValue()[0], ocspKeyAndCertificates.getValue()[1]));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificateAndUntrustedOcspIntermediate_3elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(3);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates,
            ocspKeyAndCertificates.getValue()[0], ocspKeyAndCertificates.getValue()[1]));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1])
    );

    Assert.assertEquals(CertificateValidationException.CertificateValidationStatus.UNTRUSTED, caughtException.getCertificateStatus());
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificateAndTrustedOcspIntermediateAndUntrustedOcspRoot_3elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(3);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[1]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificateAndUntrustedOcspIntermediateAndTrustedOcspRoot_3elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(3);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[2]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWithUntrustedOcspCertificateAndUntrustedOcspIntermediateAndUntrustedOcspRoot_3elementOcspChain() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(3);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    CertificateValidationException caughtException = assertThrows(
            CertificateValidationException.class,
            () -> ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1])
    );

    Assert.assertEquals(CertificateValidationException.CertificateValidationStatus.UNTRUSTED, caughtException.getCertificateStatus());
  }

  @Test
  public void getRevocationToken_ocspRespondsWith4elementCertificate_ocspRootInTsl() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(4);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[3]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  @Test
  public void getRevocationToken_ocspRespondsWith7elementCertificate_ocspFirstIntermediateInTsl() {
    CertificateToken[] signerCertificateChain = issueSignerCertificateChain(2);
    Pair<PrivateKey, X509CertificateHolder[]> ocspKeyAndCertificates = issueOcspKeyAndCertificateChain(7);
    X509Certificate ocspTrustedCertificate = TestCertificateUtil.toX509Certificate(ocspKeyAndCertificates.getValue()[5]);
    tslCertificateSource.addTSLCertificate(ocspTrustedCertificate);

    preferAiaOcsp(true);
    mockDataLoaderPostResponse(MOCK_OCSP_URL, ocspRequest -> createOcspResponse(ocspRequest, ocspKeyAndCertificates, ocspKeyAndCertificates.getValue()));
    SKOnlineOCSPSource ocspSource = createOcspSource(true);

    OCSPToken ocspToken = ocspSource.getRevocationToken(signerCertificateChain[0], signerCertificateChain[1]);

    Assert.assertNotNull(ocspToken);
  }

  private void preferAiaOcsp(boolean preferAiaOcsp) {
    Mockito.doReturn(preferAiaOcsp).when(configuration).isAiaOcspPreferred();
  }

  private CommonOCSPSource createOcspSource(boolean useNonce) {
    Mockito.doReturn(useNonce).when(configuration).isOcspNonceUsed();
    CommonOCSPSource commonOCSPSource = new CommonOCSPSource(configuration);
    commonOCSPSource.setDataLoader(ocspDataLoader);
    return commonOCSPSource;
  }

  private void mockDataLoaderPostResponse(String requestUrl, Function<byte[], byte[]> ocspResponder) {
    Mockito.doAnswer(invocationOnMock -> {
      byte[] ocspRequest = invocationOnMock.getArgument(1, byte[].class);
      return ocspResponder.apply(ocspRequest);
    }).when(ocspDataLoader).post(Mockito.eq(requestUrl), Mockito.any(byte[].class));
  }

  private static Pair<PrivateKey, X509CertificateHolder> issueCertificate(Pair<PrivateKey, X509CertificateHolder> issuer, String subjectDn, ExtensionAdder extensionAdder) {
    AsymmetricCipherKeyPair keyPair = TestKeyPairUtil.generateEcKeyPair("secp384r1");
    PrivateKey privateKey = TestKeyPairUtil.toPrivateKey((ECPrivateKeyParameters) keyPair.getPrivate());
    PublicKey publicKey = TestKeyPairUtil.toPublicKey((ECPublicKeyParameters) keyPair.getPublic());

    Instant notBefore = Instant.now();
    Instant notAfter = notBefore.plusSeconds(3600L);
    X500Name subjectDnX500Name = new X500Name(subjectDn != null ? subjectDn : String.format("CN=%s", UUID.randomUUID()));
    X500Name issuerDnX500Name = Optional
            .ofNullable(issuer)
            .map(Pair::getValue)
            .map(X509CertificateHolder::getSubject)
            .orElse(null);

    JcaX509v3CertificateBuilder certificateBuilder = TestCertificateUtil.createX509v3CertificateBuilder(
            issuerDnX500Name, null, notBefore, notAfter, subjectDnX500Name, publicKey
    );
    try {
      extensionAdder.addExtensionsTo(certificateBuilder);
    } catch (CertIOException e) {
      throw new IllegalStateException("Failed to add extension to certificate builder", e);
    }

    PrivateKey signerKey = Optional
            .ofNullable(issuer)
            .map(Pair::getKey)
            .orElse(privateKey);

    ContentSigner signer = TestCertificateUtil.createCertificateSigner(signerKey, "SHA512withECDSA");
    return Pair.of(privateKey, certificateBuilder.build(signer));
  }

  @FunctionalInterface
  private interface ExtensionAdder {
    void addExtensionsTo(JcaX509v3CertificateBuilder certificateBuilder) throws CertIOException;
  }

  private static CertificateToken[] issueSignerCertificateChain(int chainLength) {
    if (chainLength < 1) {
      throw new IllegalArgumentException("Invalid certificate chain length: " + chainLength);
    }

    Pair<PrivateKey, X509CertificateHolder> issuerKeyAndCertificate = null;
    CertificateToken[] certificateChain = new CertificateToken[chainLength];

    for (int i = 0; i < chainLength; ++i) {
      final boolean isRoot = (i == 0);
      final boolean isSigner = (i == chainLength - 1);
      String subjectDn = "CN=" + (isSigner ? "Signer" : (isRoot ? "Root" : String.format("Intermediate-%d", i)));
      Pair<PrivateKey, X509CertificateHolder> keyAndCertificate = issueCertificate(issuerKeyAndCertificate, subjectDn, certificateBuilder -> {
        certificateBuilder.addExtension(TestCertificateUtil.createBasicConstraintsExtension(true, new BasicConstraints(!isSigner)));
        if (isSigner) {
          certificateBuilder.addExtension(TestCertificateUtil.createKeyUsageExtension(false, KeyUsage.digitalSignature));
          certificateBuilder.addExtension(TestCertificateUtil.createAuthorityInfoAccessExtension(false, OCSP_ACCESS_DESCRIPTION));
        } else {
          certificateBuilder.addExtension(TestCertificateUtil.createKeyUsageExtension(false, KeyUsage.keyCertSign));
        }
      });
      issuerKeyAndCertificate = keyAndCertificate;
      certificateChain[chainLength - 1 - i] = new CertificateToken(TestCertificateUtil.toX509Certificate(keyAndCertificate.getValue()));
    }

    return certificateChain;
  }

  private static Pair<PrivateKey, X509CertificateHolder[]> issueOcspKeyAndCertificateChain(int chainLength) {
    if (chainLength < 1) {
      throw new IllegalArgumentException("Invalid certificate chain length: " + chainLength);
    }

    Pair<PrivateKey, X509CertificateHolder> issuerKeyAndCertificate = null;
    X509CertificateHolder[] certificateChain = new X509CertificateHolder[chainLength];

    for (int i = 0; i < chainLength; ++i) {
      final boolean isRoot = (i == 0);
      final boolean isResponder = (i == chainLength - 1);
      String subjectDn = "CN=" + (isResponder ? "Responder" : (isRoot ? "Root" : String.format("Intermediate-%d", i)));
      Pair<PrivateKey, X509CertificateHolder> keyAndCertificate = issueCertificate(issuerKeyAndCertificate, subjectDn, certificateBuilder -> {
        certificateBuilder.addExtension(TestCertificateUtil.createBasicConstraintsExtension(true, new BasicConstraints(!isResponder)));
        if (isResponder) {
          certificateBuilder.addExtension(TestCertificateUtil.createExtendedKeyUsageExtension(false, KeyPurposeId.id_kp_OCSPSigning));
        } else {
          certificateBuilder.addExtension(TestCertificateUtil.createKeyUsageExtension(false, KeyUsage.keyCertSign));
        }
      });
      issuerKeyAndCertificate = keyAndCertificate;
      certificateChain[chainLength - 1 - i] = keyAndCertificate.getValue();
    }

    return Pair.of(issuerKeyAndCertificate.getKey(), certificateChain);
  }

  private static byte[] createOcspResponse(byte[] ocspRequestBytes, Pair<PrivateKey, X509CertificateHolder[]> ocspSignerKeyAndCertificateChain, X509CertificateHolder... certificatesToPutIntoResponse) {
    OCSPReq request = parseOcspRequest(ocspRequestBytes);
    BasicOCSPRespBuilder basicOCSPRespBuilder = TestOcspUtil.createBasicOCSPRespBuilder(ocspSignerKeyAndCertificateChain.getValue()[0]);
    for (Req req : request.getRequestList()) {
      basicOCSPRespBuilder.addResponse(req.getCertID(), org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
    }
    ContentSigner ocspSigner = TestOcspUtil.createOcspSigner(ocspSignerKeyAndCertificateChain.getKey(), "SHA512withECDSA");
    BasicOCSPResp basicOCSPResp = TestOcspUtil.buildBasicOCSPResp(basicOCSPRespBuilder, ocspSigner, certificatesToPutIntoResponse);
    return getOcspResponseBytes(TestOcspUtil.buildSuccessfulOCSPResp(basicOCSPResp));
  }

  private static OCSPReq parseOcspRequest(byte[] ocspRequestBytes) {
    try {
      return new OCSPReq(ocspRequestBytes);
    } catch (IOException e) {
      throw new IllegalArgumentException("Invalid OCSP request", e);
    }
  }

  private static byte[] getOcspResponseBytes(OCSPResp ocspResponse) {
    try {
      return ocspResponse.getEncoded();
    } catch (IOException e) {
      throw new IllegalStateException("Failed to encode OCSP response", e);
    }
  }

}
