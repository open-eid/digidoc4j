/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package eu.europa.ec.markt.dss.validation102853.ocsp;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.bdoc.SKOcspDataLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
* SK OCSP source location.
*/
public abstract class SKOnlineOCSPSource implements OCSPSource {
  private static final Logger logger = LoggerFactory.getLogger(SKOnlineOCSPSource.class);
  
  /**
   * The data loader used to retrieve the OCSP response.
   */
  private SKOcspDataLoader dataLoader;

  private Configuration configuration;

  /**
   * SK Online OCSP Source constructor
   *
   * @param configuration configuration to use for this source
   */
  public SKOnlineOCSPSource(Configuration configuration) {
    this();
    this.configuration = configuration;
  }

  /**
   * SK Online OCSP Source constructor
   */
  public SKOnlineOCSPSource() {
    dataLoader = new SKOcspDataLoader();
  }

  /**
   * Returns SK OCSP source location.
   *
   * @return OCSP source location
   */
  public String getAccessLocation() {
    logger.debug("");
    String location = Configuration.TEST_OCSP_URL;
    if (configuration != null)
      location = configuration.getOcspSource();
    logger.debug("OCSP Access location: " + location);
    return location;
  }

  private byte[] buildOCSPRequest(final X509Certificate signCert, final X509Certificate issuerCert, Extension nonceExtension) throws
      DSSException {
    try {
      logger.debug("Building OCSP request");
      final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(signCert, issuerCert);
      final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
      ocspReqBuilder.addRequest(certId);
      ocspReqBuilder.setRequestExtensions(new Extensions(nonceExtension));

      if (configuration.hasToBeOCSPRequestSigned()) {
        logger.info("Using signed OCSP request");
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");

        if (!configuration.isOCSPSigningConfigurationAvailable()) {
          throw new ConfigurationException("Configuration needed for OCSP request signing is not complete.");
        }

        DSSPrivateKeyEntry keyEntry = getOCSPAccessCertificatePrivateKey();
        PrivateKey privateKey = ((KSPrivateKeyEntry)keyEntry).getPrivateKey();
        X509Certificate ocspSignerCert = keyEntry.getCertificate().getCertificate();

        ContentSigner contentSigner = signerBuilder.build(privateKey);
        X509CertificateHolder[] chain = {new X509CertificateHolder(ocspSignerCert.getEncoded())};
        GeneralName generalName = new GeneralName(new JcaX509CertificateHolder(ocspSignerCert).getSubject());
        ocspReqBuilder.setRequestorName(generalName);

        return ocspReqBuilder.build(contentSigner, chain).getEncoded();
      }
      return ocspReqBuilder.build().getEncoded();
    } catch (Exception e) {
      throw new DSSException(e);
    }
  }

  @Override
  public OCSPToken getOCSPToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
    logger.debug("Getting OCSP token");
    if (dataLoader == null) {
      throw new RuntimeException("Data loader is null");
    }
    try {
      final String dssIdAsString = certificateToken.getDSSIdAsString();
      if (logger.isTraceEnabled()) {
        logger.trace("--> OnlineOCSPSource queried for " + dssIdAsString);
      }
      final X509Certificate certificate = certificateToken.getCertificate();
      final X509Certificate issuerCertificate = issuerCertificateToken.getCertificate();

      final String ocspUri = getAccessLocation();
      logger.debug("Getting OCSP token from URI: " + ocspUri);
      if (ocspUri == null) {

        return null;
      }
      Extension nonceExtension = createNonce();
      final byte[] content = buildOCSPRequest(certificate, issuerCertificate, nonceExtension);

      final byte[] ocspRespBytes = dataLoader.post(ocspUri, content);

      final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);
      BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
      if(basicOCSPResp == null) {
        logger.error("OCSP response is empty");
        return null;
      }

      checkNonce(basicOCSPResp, nonceExtension);

      Date bestUpdate = null;
      SingleResp bestSingleResp = null;
      final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificate, issuerCertificate);
      for (final SingleResp singleResp : basicOCSPResp.getResponses()) {

        if (DSSRevocationUtils.matches(certId, singleResp)) {

          final Date thisUpdate = singleResp.getThisUpdate();
          if (bestUpdate == null || thisUpdate.after(bestUpdate)) {

            bestSingleResp = singleResp;
            bestUpdate = thisUpdate;
          }
        }
      }
      if (bestSingleResp != null) {

        final OCSPToken ocspToken = new OCSPToken(basicOCSPResp, bestSingleResp);
        ocspToken.setSourceURI(ocspUri);
        certificateToken.setRevocationToken(ocspToken);
        return ocspToken;
      }
    } catch (OCSPException e) {
      logger.error("OCSP error: " + e.getMessage(), e);
    } catch (IOException e) {
      throw new DSSException(e);
    }
    return null;
  }

  protected void checkNonce(BasicOCSPResp basicOCSPResp, Extension expectedNonceExtension) {
    final Extension extension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    final DEROctetString expectedNonce = (DEROctetString) expectedNonceExtension.getExtnValue();
    final DEROctetString receivedNonce = (DEROctetString) extension.getExtnValue();
    if (!receivedNonce.equals(expectedNonce)) {
      throw new DigiDoc4JException("The OCSP request was the victim of replay attack: nonce[sent:" + expectedNonce + "," +
          " received:" + receivedNonce);
    }
  }

  abstract Extension createNonce();

  private DSSPrivateKeyEntry getOCSPAccessCertificatePrivateKey() {
    Pkcs12SignatureToken signatureTokenConnection = new Pkcs12SignatureToken(configuration.getOCSPAccessCertificatePassword(), configuration.getOCSPAccessCertificateFileName());
    return signatureTokenConnection.getKeys().get(0);
  }

  void setDataLoader(SKOcspDataLoader dataLoader) {
    this.dataLoader = dataLoader;
  }

  public void setUserAgentSignatureProfile(SignatureProfile signatureProfile) {
    dataLoader.setUserAgentSignatureProfile(signatureProfile);
  }
}
