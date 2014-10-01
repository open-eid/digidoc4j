package eu.europa.ec.markt.dss.validation102853.ocsp;

import eu.europa.ec.markt.dss.DSSRevocationUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.https.OCSPDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.digidoc4j.Configuration;
import org.digidoc4j.Signer;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.signers.PKCS12Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * SK OCSP source location.
 */
public class SKOnlineOCSPSource implements OCSPSource {
  final Logger logger = LoggerFactory.getLogger(SKOnlineOCSPSource.class);

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

  private byte[] buildOCSPRequest(final X509Certificate signCert, final X509Certificate issuerCert) throws
      DSSException {
    try {
      final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(signCert, issuerCert);
      final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
      ocspReqBuilder.addRequest(certId);

      if (configuration.hasToBeOCSPRequestSigned()) {
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");

        if (!configuration.isOCSPSigningConfigurationAvailable())
          throw new ConfigurationException("Configuration needed for OCSP request signing is not complete.");

        Signer ocspSigner = new PKCS12Signer(configuration.getOCSPAccessCertificateFileName(),
            configuration.getOCSPAccessCertificatePassword());

        ContentSigner contentSigner = signerBuilder.build(ocspSigner.getPrivateKey());
        X509Certificate ocspSignerCert = ocspSigner.getCertificate().getX509Certificate();
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
  public BasicOCSPResp getOCSPResponse(final X509Certificate certificate, final X509Certificate issuerCertificate) {
    if (dataLoader == null) {
      throw new DSSNullException(DataLoader.class);
    }
    try {
      final String ocspUri = getAccessLocation();
      if (logger.isDebugEnabled()) {
        logger.debug("OCSP URI: " + ocspUri);
      }
      if (ocspUri == null) {

        return null;
      }
      final byte[] content = buildOCSPRequest(certificate, issuerCertificate);

      final byte[] ocspRespBytes = dataLoader.post(ocspUri, content);

      final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);
      try {
        return (BasicOCSPResp) ocspResp.getResponseObject();
      } catch (NullPointerException e) {
        logger.error("OCSP error: Encountered a case when the OCSPResp is initialised with a null OCSP response...", e);
      }
    } catch (OCSPException e) {

      logger.error("OCSP error: " + e.getMessage(), e);
    } catch (IOException e) {
      throw new DSSException(e);
    }
    return null;
  }

}
