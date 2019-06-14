/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.ocsp;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.ServiceType;
import org.digidoc4j.exceptions.CertificateValidationException;
import org.digidoc4j.exceptions.CertificateValidationException.CertificateValidationStatus;
import org.digidoc4j.exceptions.ServiceAccessDeniedException;
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
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

  private X509Certificate issuerCert;

  @Mock
  private SkOCSPDataLoader dataLoader;

  @Test
  public void getOCSPToken_whenOCSPResponseIsUnauthorized_thenThrowAccessDeniedException() {
    when(dataLoader.post(anyString(), any(byte[].class))).thenReturn(new byte[]{48, 3, 10, 1, 6});

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    ocspSource.setDataLoader(dataLoader);
    try {
      ocspSource.getRevocationToken(new CertificateToken(TestSigningUtil.SIGN_CERT), new CertificateToken(this.issuerCert));
      fail("Expected to throw ServiceAccessDeniedException");
    } catch (ServiceAccessDeniedException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals("Access denied to OCSP service <" + configuration.getOcspSource() + ">", e.getMessage());
      assertEquals(configuration.getOcspSource(), e.getServiceUrl());
    }
  }

  @Test
  public void getValidCertificateOCSPToken() throws CertificateEncodingException {
    CommonOCSPCertificateSource certificateSource = new CommonOCSPCertificateSource();
    certificateSource.addCertificate(new CertificateToken(openX509Certificate(Paths.get("src/test/resources/testFiles/certs/EE_Certification_Centre_Root_CA.pem.crt"))));

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/ESTEID-SK_2011.pem.crt"));
    CertificateToken issuerCertificateToken = getIssuerCertificateToken(subjectCertificate, certificateSource);

    SKOnlineOCSPSource ocspSource = constructOCSPSource();
    OCSPToken revocationToken = ocspSource.getRevocationToken(new CertificateToken(subjectCertificate), issuerCertificateToken);
    assertTrue(revocationToken.getStatus());
  }

  @Test
  public void getRevokedCertificateOCSPToken_shouldThrowCertificateRevokedException() throws CertificateEncodingException {
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
    }
  }

  @Test
  public void getTestCertificateOCSPTokenFromProdOCSP_shouldThrowCertificateUnknownException() throws CertificateException {
    CommonOCSPCertificateSource certificateSource = new CommonOCSPCertificateSource();
    certificateSource.addCertificate(new CertificateToken(openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofESTEID-SK2011.crt"))));

    X509Certificate subjectCertificate = openX509Certificate(Paths.get("src/test/resources/testFiles/certs/TESTofStatusRevoked.cer"));
    CertificateToken issuerCertificateToken = getIssuerCertificateToken(subjectCertificate, certificateSource);

    SKOnlineOCSPSource ocspSource = (SKOnlineOCSPSource) OCSPSourceBuilder.defaultOCSPSource()
          .withConfiguration(Configuration.of(Configuration.Mode.PROD))
          .build();
    try {
      ocspSource.getRevocationToken(new CertificateToken(subjectCertificate), issuerCertificateToken);
      fail("Expected to throw CertificateValidationException");
    } catch (CertificateValidationException e) {
      assertEquals("Certificate is unknown", e.getMessage());
      assertSame(CertificateValidationStatus.UNKNOWN, e.getCertificateStatus());
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
  public void ocspRespondsWithEmptyBody_technicalExceptionIsThrown() throws CertificateEncodingException {
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
    }
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
    X500Principal subjectPrincipal = subjectCertificateToken.getIssuerX500Principal();
    return certificateSource.get(subjectPrincipal).get(0);
  }

  private X509Certificate createRandomCertificate() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
    Security.addProvider(new BouncyCastleProvider());
    X500Name name = new X500Name("cn=Me");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(new BouncyCastleProvider()).build(keyPair.getPrivate());

    X509CertificateHolder certificateHolder = new X509v3CertificateBuilder(
            name,
            BigInteger.ONE,
            new Date(),
            new Date(new Date().getTime() + (1000 * 60 * 60 * 24)),
            name,
            SubjectPublicKeyInfo.getInstance(keyPair.getPublic())).build(signer);

    return new JcaX509CertificateConverter().getCertificate(certificateHolder);
  }
}
