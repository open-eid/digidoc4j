/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.ServiceType;
import org.digidoc4j.exceptions.*;
import org.digidoc4j.exceptions.CertificateValidationException.CertificateValidationStatus;
import org.digidoc4j.impl.CommonOCSPCertificateSource;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.SkOCSPDataLoader;
import org.digidoc4j.test.util.TestSigningUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.digidoc4j.Configuration.Mode.TEST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SKOnlineOCSPSourceTest extends AbstractTest {

  private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");
  private X509Certificate issuerCert;

  @Mock
  private SkOCSPDataLoader dataLoader;

  @Test
  public void getValidCertificateOCSPToken() throws CertificateEncodingException {
    CommonOCSPCertificateSource certificateSource = new CommonOCSPCertificateSource();
    certificateSource.addCertificate(new CertificateToken(openX509Certificate(Paths.get("src/test/resources/testFiles/certs/EE_Certification_Centre_Root_CA.pem.crt"))));

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/ESTEID-SK_2011.pem.crt"));
    CertificateToken issuerCertificateToken = getIssuerCertificateToken(subjectCertificate, certificateSource);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    OCSPToken revocationToken = ocspSource.getRevocationToken(new CertificateToken(subjectCertificate), issuerCertificateToken);
    assertEquals(CertificateStatus.GOOD, revocationToken.getStatus());
  }

  @Test
  public void getRevokedCertificateOCSPToken_thenThrowRevokedCertificateValidationException() throws CertificateEncodingException {
    CommonOCSPCertificateSource certificateSource = new CommonOCSPCertificateSource();
    certificateSource.addCertificate(new CertificateToken(openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt"))));

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofStatusRevoked.cer"));
    CertificateToken issuerCertificateToken = getIssuerCertificateToken(subjectCertificate, certificateSource);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    try {
      ocspSource.getRevocationToken(new CertificateToken(subjectCertificate), issuerCertificateToken);
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertEquals("Certificate status is revoked", e.getMessage());
      assertSame(CertificateValidationStatus.REVOKED, e.getCertificateStatus());
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(this.configuration.getOcspSource(), e.getServiceUrl());
    }
  }

  @Test
  public void getTestCertificateOCSPTokenFromProdOCSP_thenThrowUnknownCertificateValidationException() throws CertificateException {
    CommonOCSPCertificateSource certificateSource = new CommonOCSPCertificateSource();
    certificateSource.addCertificate(new CertificateToken(openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt"))));

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofStatusRevoked.cer"));
    CertificateToken issuerCertificateToken = getIssuerCertificateToken(subjectCertificate, certificateSource);

    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    SKOnlineOCSPSource ocspSource = (SKOnlineOCSPSource) OCSPSourceBuilder.defaultOCSPSource()
            .withConfiguration(configuration)
            .build();
    try {
      ocspSource.getRevocationToken(new CertificateToken(subjectCertificate), issuerCertificateToken);
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertEquals("Certificate is unknown", e.getMessage());
      assertSame(CertificateValidationStatus.UNKNOWN, e.getCertificateStatus());
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
    }
  }

  @Test
  public void ocspAccessSettingsInvalid_throwsServiceAccessDeniedException() throws CertificateEncodingException {
    Configuration configuration = Configuration.of(TEST);
    configuration.setSignOCSPRequests(true);
    configuration.setOCSPAccessCertificateFileName("src/test/resources/testFiles/p12/signout.p12");
    configuration.setOCSPAccessCertificatePassword("test".toCharArray());

    SKOnlineOCSPSource ocspSource = (SKOnlineOCSPSource) OCSPSourceBuilder.defaultOCSPSource()
            .withConfiguration(configuration)
            .build();

    CommonOCSPCertificateSource certificateSource = new CommonOCSPCertificateSource();
    certificateSource.addCertificate(new CertificateToken(openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofEECertificationCentreRootCA.crt"))));

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt"));
    CertificateToken issuerCertificateToken = getIssuerCertificateToken(subjectCertificate, certificateSource);

    try {
      ocspSource.getRevocationToken(new CertificateToken(subjectCertificate), issuerCertificateToken);
      fail("Expected to throw ServiceAccessDeniedException");
    } catch (ServiceAccessDeniedException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertEquals("Access denied to OCSP service <" + configuration.getOcspSource() + ">", e.getMessage());
    }
  }

  @Test
  public void ocspRespondsWithEmptyBody_thenThrowTechnicalCertificateValidationException() throws CertificateEncodingException {
    CommonOCSPCertificateSource certificateSource = new CommonOCSPCertificateSource();
    certificateSource.addCertificate(new CertificateToken(openX509Certificate(Paths.get("src/test/resources/testFiles/certs/EE_Certification_Centre_Root_CA.pem.crt"))));

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/ESTEID-SK_2011.pem.crt"));
    CertificateToken issuerCertificateToken = getIssuerCertificateToken(subjectCertificate, certificateSource);

    when(dataLoader.post(anyString(), any(byte[].class))).thenReturn(new byte[]{});
    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);

    try {
      ocspSource.getRevocationToken(new CertificateToken(subjectCertificate), issuerCertificateToken);
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertEquals("Failed to parse OCSP response", e.getMessage());
      assertSame(CertificateValidationStatus.TECHNICAL, e.getCertificateStatus());
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(this.configuration.getOcspSource(), e.getServiceUrl());
    }
  }

  @Test
  public void getOCSPToken_malformedOCSPRequest_thenThrowTechnicalCertificateValidationException() {
    mockOcspResponse(OCSPResponseStatus.MALFORMED_REQUEST);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertSame(CertificateValidationStatus.TECHNICAL, e.getCertificateStatus());
      assertEquals("OCSP request malformed", e.getMessage());
    }
  }

  @Test
  public void getOCSPToken_ocspServiceInternalError_thenThrowTechnicalCertificateValidationException() {
    mockOcspResponse(OCSPResponseStatus.INTERNAL_ERROR);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertSame(CertificateValidationStatus.TECHNICAL, e.getCertificateStatus());
      assertEquals("OCSP service internal error", e.getMessage());
    }
  }

  @Test
  public void getOCSPToken_ocspResponseTryLater_thenThrowServiceUnavailableException() {
    mockOcspResponse(OCSPResponseStatus.TRY_LATER);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw ServiceUnavailableException");
    } catch (ServiceUnavailableException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertEquals("Connection to OCSP service <" + configuration.getOcspSource() + "> is unavailable, try again later", e.getMessage());
    }
  }

  @Test
  public void getOCSPToken_ocspRequestNotSigned_thenThrowTechnicalCertificateValidationException() {
    mockOcspResponse(OCSPResponseStatus.SIG_REQUIRED);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertSame(CertificateValidationStatus.TECHNICAL, e.getCertificateStatus());
      assertEquals("OCSP request not signed", e.getMessage());
    }
  }

  @Test
  public void getOCSPToken_whenOCSPResponseIsUnauthorized_thenThrowAccessDeniedException() {
    mockOcspResponse(OCSPResponseStatus.UNAUTHORIZED);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw ServiceAccessDeniedException");
    } catch (ServiceAccessDeniedException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertEquals("Access denied to OCSP service <" + configuration.getOcspSource() + ">", e.getMessage());
    }
  }

  @Test
  public void getOCSPToken_unhandledOcspResponseStatus_thenThrowTechnicalCertificateValidationException() {
    mockOcspResponse(7);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertSame(CertificateValidationStatus.TECHNICAL, e.getCertificateStatus());
      assertEquals("OCSP service responded with unknown status <7>", e.getMessage());
    }
  }

  @Test
  public void getOCSPToken_failedToParseOCSPResponse_thenThrowTechnicalCertificateValidationException() {
    String response = "INVALID_RESPONSE_FORMAT";
    when(dataLoader.post(anyString(), any(byte[].class))).thenReturn(response.getBytes(StandardCharsets.UTF_8));

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertSame(CertificateValidationStatus.TECHNICAL, e.getCertificateStatus());
      assertEquals("Failed to parse OCSP response", e.getMessage());
    }
  }

  @Test
  public void getOCSPToken_nonceValidationFailed_thenThrowUntrustedCertificateValidationException() {
    String response = "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";
    when(dataLoader.post(anyString(), any(byte[].class))).thenReturn(Base64.decode(response));

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
      assertSame(CertificateValidationStatus.UNTRUSTED, e.getCertificateStatus());
      assertTrue(e.getMessage().startsWith("The OCSP request was victim of the replay attack"));
    }
  }

  @Test
  public void getOCSPToken_ocspCertificateExpired() throws Exception {
    this.expectedException.expect(CertificateValidationException.class);
    this.expectedException.expectMessage("OCSP response certificate <C-E83A008AF341579A76367AF41CDD371F7F35E949220FC4621A3F2596A73D1D05> is expired or not yet valid");

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/SK-OCSP-RESPONDER-2011_test.cer"));
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    SKOnlineOCSPSource ocspSource = (SKOnlineOCSPSource) OCSPSourceBuilder.defaultOCSPSource()
            .withConfiguration(configuration)
            .build();

    Date producedAt = this.dateFormat.parse("08.09.2024");
    ocspSource.verifyOcspResponderCertificate(new CertificateToken(subjectCertificate), producedAt);
  }

  @Test
  public void getOCSPToken_ocspCertificateNotYetValid() throws Exception {
    this.expectedException.expect(CertificateValidationException.class);
    this.expectedException.expectMessage("OCSP response certificate <C-E83A008AF341579A76367AF41CDD371F7F35E949220FC4621A3F2596A73D1D05> is expired or not yet valid");

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/SK-OCSP-RESPONDER-2011_test.cer"));
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    SKOnlineOCSPSource ocspSource = (SKOnlineOCSPSource) OCSPSourceBuilder.defaultOCSPSource()
            .withConfiguration(configuration)
            .build();

    Date producedAt = this.dateFormat.parse("06.03.2011");
    ocspSource.verifyOcspResponderCertificate(new CertificateToken(subjectCertificate), producedAt);
  }

  @Test
  public void getOCSPToken_anyDSSExceptionRethrownAsTechnicalException() {
    expectedException.expectMessage("OCSP request failed");
    expectedException.expect(TechnicalException.class);

    when(dataLoader.post(anyString(), any(byte[].class))).thenThrow(DSSException.class);
    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
  }

  @Test
  public void dataLoaderMissing() {
    expectedException.expectMessage("Data loader is null");
    expectedException.expect(TechnicalException.class);
    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(null);
    ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    Security.addProvider(new BouncyCastleProvider());
    this.configuration = Configuration.of(TEST);
    this.issuerCert = this.openX509Certificate(
            Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt")); //Any certificate will do
  }

  private SKOnlineOCSPSource constructOCSPSource() {
    return (SKOnlineOCSPSource) OCSPSourceBuilder.defaultOCSPSource()
            .withConfiguration(configuration)
            .build();
  }

  private CertificateToken getIssuerCertificateToken(X509Certificate subjectCertificate, CertificateSource certificateSource) throws CertificateEncodingException {
    CertificateToken subjectCertificateToken = DSSUtils.loadCertificate(subjectCertificate.getEncoded());
    final String canonicalizedIssuerName = subjectCertificateToken.getIssuerX500Principal().getName(X500Principal.CANONICAL);
    return certificateSource.getCertificates().stream()
            .filter(ct -> ct.getSubject().getCanonical().equals(canonicalizedIssuerName))
            .findFirst().orElseThrow(() -> new IllegalStateException("No issuer certificate token found"));
  }

  private void mockOcspResponse(int ocspResponseStatus) {
    byte[] ocspResponse = {48, 3, 10, 1, (byte) ocspResponseStatus};
    when(dataLoader.post(anyString(), any(byte[].class))).thenReturn(ocspResponse);
  }
}
