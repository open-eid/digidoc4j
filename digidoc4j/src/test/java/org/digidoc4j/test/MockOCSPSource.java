/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonCertificateSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;


public class MockOCSPSource implements OCSPSource {

  private static final Logger LOGGER = LoggerFactory.getLogger(MockOCSPSource.class);
  private final PrivateKey key;
  private final X509Certificate certificate;
  private CertificateStatus expectedResponse = CertificateStatus.GOOD;
  private Date ocspDate = new Date();

  static {
    try {
      Security.addProvider(new BouncyCastleProvider());
    } catch (Throwable e) {
      e.printStackTrace();
    }
  }

  /**
   * The default constructor for MockConfigurableOCSPSource using "src/test/resources/ocsp.p12" file as OCSP responses source.
   */
  public MockOCSPSource() { // TODO
    this("testFiles/ocsp.p12", "password");
  }

  /**
   * The default constructor for MockOCSPSource.
   *
   * @param pkcs12FilePath
   * @param password
   * @throws Exception
   */
  public MockOCSPSource(final String pkcs12FilePath, final String password) {
    try (FileInputStream stream = new FileInputStream(pkcs12FilePath)) {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(stream, password.toCharArray());
      String alias = keyStore.aliases().nextElement();
      this.certificate = (X509Certificate) keyStore.getCertificate(alias);
      this.key = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
      if (LOGGER.isTraceEnabled()) {
        CertificateToken certificateToken = new CommonCertificateSource().addCertificate(new CertificateToken(this.certificate));
        LOGGER.trace("Mock OCSP source with signing certificate: {}", certificateToken);
      }
    } catch (Exception e) {
      throw new DSSException(e);
    }
  }

  @Override
  public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
    try {
      BigInteger serialNumber = certificateToken.getCertificate().getSerialNumber();
      X509Certificate issuerCertificate = issuerCertificateToken.getCertificate();
      OCSPReq ocspRequest = generateOCSPRequest(issuerCertificate, serialNumber);
      BasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(issuerCertificate.getPublicKey(), this.getSHA1DigestCalculator());
      Extension extension = ocspRequest.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
      if (extension != null) {
        builder.setResponseExtensions(new Extensions(new Extension[]{extension}));
      }
      for (Req request : ocspRequest.getRequestList()) {
        final CertificateID certificateID = request.getCertID();
        boolean isOK = true; // TODO Whaat?
        if (isOK) {
          builder.addResponse(certificateID, CertificateStatus.GOOD, this.ocspDate, null, null);
        } else {
          builder.addResponse(certificateID, new RevokedStatus(DateUtils.addDays(this.ocspDate, -1), CRLReason.privilegeWithdrawn));
        }
      }
      X509CertificateHolder[] chain = {new X509CertificateHolder(issuerCertificate.getEncoded()), new X509CertificateHolder(this.certificate.getEncoded())};
      OCSPToken token = new OCSPToken();
      token.setBasicOCSPResp(builder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(this.key), chain, this.ocspDate));
      token.setCertId(DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken));
      token.extractInfo();
      return token;
    } catch (OCSPException e) {
      throw new DSSException(e);
    } catch (IOException e) {
      throw new DSSException(e);
    } catch (CertificateEncodingException e) {
      throw new DSSException(e);
    } catch (OperatorCreationException e) {
      throw new DSSException(e);
    }
  }

  /**
   * This method allows to set the status of the cert to GOOD.
   */
  public void setGoodStatus() {
    this.expectedResponse = CertificateStatus.GOOD;
  }

  /**
   * This method allows to set the status of the cert to UNKNOWN.
   */
  public void setUnknownStatus() {
    this.expectedResponse = new UnknownStatus();
  }

  /**
   * This method allows to set the status of the cert to REVOKED.
   * <p/>
   * unspecified = 0; keyCompromise = 1; cACompromise = 2; affiliationChanged = 3; superseded = 4; cessationOfOperation
   * = 5; certificateHold = 6; // 7 -> unknown removeFromCRL = 8; privilegeWithdrawn = 9; aACompromise = 10;
   *
   * @param revocationDate
   * @param revocationReasonId
   */
  public void setRevokedStatus(Date revocationDate, int revocationReasonId) {
    this.expectedResponse = new RevokedStatus(revocationDate, revocationReasonId);
  }

  /**
   * @param issuerCert
   * @param serialNumber
   * @return
   * @throws DSSException
   */
  public OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws DSSException {
    try {
      final DigestCalculator digestCalculator = getSHA1DigestCalculator();
      // Generate the getFileId for the certificate we are looking for
      // basic request generation with nonce
      OCSPReqBuilder ocspGen = new OCSPReqBuilder();
      ocspGen.addRequest(new CertificateID(digestCalculator, new X509CertificateHolder(issuerCert.getEncoded()), serialNumber));
      // create details for nonce extension
      BigInteger nonce = BigInteger.valueOf(this.ocspDate.getTime());
      ocspGen.setRequestExtensions(new Extensions(new Extension[]{new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()))}));
      return ocspGen.build();
    } catch (OCSPException e) {
      throw new DSSException(e);
    } catch (IOException e) {
      throw new DSSException(e);
    } catch (CertificateEncodingException e) {
      throw new DSSException(e);
    }
  }

  public static DigestCalculator getSHA1DigestCalculator() throws DSSException {

    try {
      JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
      jcaDigestCalculatorProviderBuilder.setProvider("BC");
      final DigestCalculatorProvider digestCalculatorProvider = jcaDigestCalculatorProviderBuilder.build();
      final DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
      return digestCalculator;
    } catch (OperatorCreationException e) {
      throw new DSSException(e);
    }
  }

  /*
   * ACCESSORS
   */

  public CertificateStatus getExpectedResponse() {
    return expectedResponse;
  }

  public void setOcspDate(Date ocspDate) {
    this.ocspDate = ocspDate;
  }

}
