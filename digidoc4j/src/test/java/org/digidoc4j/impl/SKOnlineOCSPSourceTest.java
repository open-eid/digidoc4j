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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.ServiceType;
import org.digidoc4j.exceptions.CertificateValidationException;
import org.digidoc4j.exceptions.CertificateValidationException.CertificateValidationStatus;
import org.digidoc4j.exceptions.ServiceAccessDeniedException;
import org.digidoc4j.exceptions.ServiceUnavailableException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.test.util.TestSigningUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.Security;
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
  public void ocspResponseWithCaCertificate() throws IOException {
    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/d-trust-ca.cer"));
    this.configuration.getTSL().addTSLCertificate(subjectCertificate);
    SKOnlineOCSPSource skOnlineOCSPSource = Mockito.spy(constructOCSPSource());
    BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPBase64Encoded(
            "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");
    skOnlineOCSPSource.verifyOCSPResponse(basicOCSPResp);
    Mockito.verify(skOnlineOCSPSource, Mockito.times(1)).verifyOcspResponderCertificate(any(), any());
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
