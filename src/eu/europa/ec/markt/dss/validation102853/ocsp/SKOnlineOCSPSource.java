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

import eu.europa.ec.markt.dss.DSSRevocationUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.https.OCSPDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.digidoc4j.Configuration;
import org.digidoc4j.Signer;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
* SK OCSP source location.
*/
public abstract class SKOnlineOCSPSource implements OCSPSource {
  final Logger logger = LoggerFactory.getLogger(SKOnlineOCSPSource.class);

  // TODO: A hack for testing, to be removed later
  public static volatile Listener listener = null;
  
  /**
   * The data loader used to retrieve the OCSP response.
   */
  private DataLoader dataLoader;

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
    dataLoader = new OCSPDataLoader();
  }

  /**
   * Returns SK OCSP source location.
   *
   * @return OCSP source location
   */
  public String getAccessLocation() {
    logger.debug("");
    String location = "http://www.openxades.org/cgi-bin/ocsp.cgi";
    if (configuration != null)
      location = configuration.getOcspSource();
    logger.debug("OCSP Access location: " + location);
    return location;
  }

  private byte[] buildOCSPRequest(final X509Certificate signCert, final X509Certificate issuerCert, Extension nonceExtension) throws
      DSSException {
    try {
      final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(signCert, issuerCert);
      final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
      ocspReqBuilder.addRequest(certId);
      ocspReqBuilder.setRequestExtensions(new Extensions(nonceExtension));

      if (configuration.hasToBeOCSPRequestSigned()) {
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");

        if (!configuration.isOCSPSigningConfigurationAvailable()) {
          throw new ConfigurationException("Configuration needed for OCSP request signing is not complete.");
        }

        Signer ocspSigner = new PKCS12Signer(configuration.getOCSPAccessCertificateFileName(),
            configuration.getOCSPAccessCertificatePassword());

        ContentSigner contentSigner = signerBuilder.build(ocspSigner.getPrivateKey());
        X509Certificate ocspSignerCert = ocspSigner.getCertificate();
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

  /**
   * sets given string as http header User-Agent
   *
   * @param userAgent user agent value
   */
  public void setUserAgent(String userAgent) {
    ((CommonsDataLoader) dataLoader).setUserAgent(userAgent);
  }

  @Override
  public OCSPToken getOCSPToken(CertificateToken certificateToken, CertificatePool certificatePool) {
    if(listener != null) {
      listener.onGetOCSPToken(certificateToken, certificatePool);
    }
    if (dataLoader == null) {
      throw new DSSNullException(DataLoader.class);
    }
    try {
      final String dssIdAsString = certificateToken.getDSSIdAsString();
      if (logger.isTraceEnabled()) {
        logger.trace("--> OnlineOCSPSource queried for " + dssIdAsString);
      }
      final X509Certificate certificate = certificateToken.getCertificate();
//      final X509Certificate issuerCertificate = certificateToken.getIssuerToken().getCertificate();
      X500Principal issuerX500Principal = certificateToken.getIssuerX500Principal();
      List<CertificateToken> issuerTokens = certificatePool.get(issuerX500Principal);

      if (issuerTokens == null || issuerTokens.size() == 0)
        throw new DSSException("Not possible to find issuer " + issuerX500Principal + " certificate");
      final X509Certificate issuerCertificate = issuerTokens.get(0).getCertificate();

      final String ocspUri = getAccessLocation();
      if (logger.isDebugEnabled()) {
        logger.debug("OCSP URI: " + ocspUri);
      }
      if (ocspUri == null) {

        return null;
      }
      Extension nonceExtension = createNonce();
      final byte[] content = buildOCSPRequest(certificate, issuerCertificate, nonceExtension);

      final byte[] ocspRespBytes = dataLoader.post(ocspUri, content);

      final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);
      BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();

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

        final OCSPToken ocspToken = new OCSPToken(basicOCSPResp, bestSingleResp, certificatePool);
        ocspToken.setSourceURI(ocspUri);
        certificateToken.setRevocationToken(ocspToken);
        return ocspToken;
      }
    } catch (NullPointerException e) {
      logger.error("OCSP error: Encountered a case when the OCSPResp is initialised with a null OCSP response...", e);
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
  
  public interface Listener {

    void onGetOCSPToken(CertificateToken certificateToken, CertificatePool certificatePool);
      
  }
}
