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

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.digidoc4j.Configuration;
import org.digidoc4j.ConfigurationParameter;
import org.digidoc4j.Constant;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureVerificationException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

/**
 * SK OCSP source location.
 */
public abstract class SKOnlineOCSPSource implements OCSPSource {

  private final Logger log = LoggerFactory.getLogger(SKOnlineOCSPSource.class);
  private SkDataLoader dataLoader;
  private Configuration configuration;

  /**
   * SK Online OCSP Source constructor
   *
   * @param configuration configuration to use for this source
   */
  public SKOnlineOCSPSource(Configuration configuration) {
    this.configuration = configuration;
  }

  /**
   * Returns SK OCSP source location.
   *
   * @return OCSP source location
   */
  public String getAccessLocation() {
    if (this.configuration != null) {
      return this.configuration.getOcspSource();
    }
    return Constant.Test.OCSP_SOURCE;
  }

  @Override
  public OCSPToken getOCSPToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
    this.log.debug("Getting OCSP token ...");
    try {
      if (this.dataLoader == null) {
        throw new TechnicalException("Data loader is null");
      }
      if (this.log.isTraceEnabled()) {
        this.log.trace("Querying by DSS ID <{}>", certificateToken.getDSSIdAsString());
      }
      CertificateID certificateID = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken);
      Extension nonceExtension = this.createNonce();
      BasicOCSPResp response = (BasicOCSPResp) new OCSPResp(this.dataLoader.post(this.getAccessLocation(),
          this.buildRequest(certificateID, nonceExtension))).getResponseObject();
      if (response == null) {
        this.log.warn("Basic OCSP response is empty");
        return null;
      }
      this.verifyResponse(response);
      this.checkNonce(response, nonceExtension);
      OCSPToken token = new OCSPToken();
      token.setBasicOCSPResp(response);
      token.setCertId(certificateID);
      token.setSourceURL(this.getAccessLocation());
      token.extractInfo();
      if (token.getThisUpdate() == null) {
        this.log.warn("No best single match of OCSP response found");
        return null;
      }
      certificateToken.addRevocationToken(token);
      return token;
    } catch (DigiDoc4JException e) {
      throw e; // TODO should we throw only DSS exceptions?
    } catch (Exception e) {
      throw new DSSException(e);
    }
  }

  /*
   * RESTRICTED METHODS
   */

  protected abstract Extension createNonce();

  protected void checkNonce(BasicOCSPResp response, Extension expectedNonceExtension) {
    Extension extension = response.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    DEROctetString expectedNonce = (DEROctetString) expectedNonceExtension.getExtnValue();
    DEROctetString receivedNonce = (DEROctetString) extension.getExtnValue();
    if (!receivedNonce.equals(expectedNonce)) {
      throw new DigiDoc4JException(
          String.format("The OCSP request was the victim of replay attack (nonce sent <%s>, nonce received <%s>)",
              expectedNonce, receivedNonce));
    }
  }

  private byte[] buildRequest(final CertificateID certificateID, Extension nonceExtension) throws DSSException {
    try {
      this.log.debug("Building OCSP request ...");
      OCSPReqBuilder builder = new OCSPReqBuilder();
      builder.addRequest(certificateID);
      builder.setRequestExtensions(new Extensions(nonceExtension));
      if (this.configuration.hasToBeOCSPRequestSigned()) {
        this.log.info("Using signed OCSP request ...");
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        if (!this.configuration.isOCSPSigningConfigurationAvailable()) {
          throw new ConfigurationException("Configuration needed for OCSP request signing is not complete");
        }
        DSSPrivateKeyEntry privateKeyEntry = this.getOCSPAccessCertificatePrivateKey();
        X509Certificate signingCertificate = privateKeyEntry.getCertificate().getCertificate();
        builder.setRequestorName(new GeneralName(new JcaX509CertificateHolder(signingCertificate).getSubject()));
        return builder.build(signerBuilder.build(((KSPrivateKeyEntry) privateKeyEntry).getPrivateKey()),
            new X509CertificateHolder[]{new X509CertificateHolder(signingCertificate.getEncoded())}).getEncoded();
      }
      return builder.build().getEncoded();
    } catch (Exception e) {
      throw new DSSException(e);
    }
  }

  private void verifyResponse(BasicOCSPResp response) {
    String verificationCertificatePath = this.configuration.getOCSPResponseVerificationCertificatePath();
    if (StringUtils.isNotBlank(verificationCertificatePath)) {
      try {
        X509Certificate verificationCertificate = Helper.loadCertificate(verificationCertificatePath);
        ContentVerifierProvider provider = new JcaContentVerifierProviderBuilder().setProvider("BC").build(new
            X509CertificateHolder(verificationCertificate.getEncoded()));
        if (!response.isSignatureValid(provider)) {
          throw new SignatureVerificationException("OCSP response signature is invalid");
        }
      } catch (SignatureVerificationException e) {
        throw e;
      } catch (Exception e) {
        throw new SignatureVerificationException("Unable to verify response signature", e);
      }
    } else {
      if (!this.configuration.isTest()) {
        String warningMessage = String.format("It's strictly recommended to use signature verification of OCSP response. " +
            "Configure <%s> parameter to activate", ConfigurationParameter.OcspResponseVerificationCertificatePath);
        this.log.warn(StringUtils.rightPad("-", warningMessage.length(), "-"));
        this.log.warn(warningMessage);
        this.log.warn(StringUtils.rightPad("-", warningMessage.length(), "-"));
      }
    }
  }

  private DSSPrivateKeyEntry getOCSPAccessCertificatePrivateKey() throws IOException {
    Pkcs12SignatureToken signatureTokenConnection = new Pkcs12SignatureToken(
        this.configuration.getOCSPAccessCertificateFileName(), this.configuration
        .getOCSPAccessCertificatePasswordAsString());
    return signatureTokenConnection.getKeys().get(0);
  }

  /*
   * ACCESSORS
   */

  /**
   * Gets configuration
   *
   * @return Configuration
   */
  public Configuration getConfiguration() {
    return configuration;
  }

  /**
   * Gets data loader
   *
   * @return SkDataLoader
   */
  public SkDataLoader getDataLoader() {
    return dataLoader;
  }

  /**
   * Define data loader.
   *
   * @param dataLoader Data loader object to be used.
   */
  public void setDataLoader(SkDataLoader dataLoader) {
    this.dataLoader = dataLoader;
  }

}
