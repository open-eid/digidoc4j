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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.apache.commons.collections4.CollectionUtils;
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
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.ServiceType;
import org.digidoc4j.exceptions.CertificateValidationException;
import org.digidoc4j.exceptions.CertificateValidationException.CertificateValidationStatus;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.ServiceAccessDeniedException;
import org.digidoc4j.exceptions.ServiceUnavailableException;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * SK OCSP source location.
 */
public abstract class SKOnlineOCSPSource implements OCSPSource {

  public static final String OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
  private static final Logger LOGGER = LoggerFactory.getLogger(SKOnlineOCSPSource.class);

  private DataLoader dataLoader;
  private Configuration configuration;

  /**
   * SK Online OCSP Source constructor
   *
   * @param configuration configuration to use for this source
   */
  public SKOnlineOCSPSource(Configuration configuration) {
    this.configuration = configuration;
  }

  @Override
  public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
    LOGGER.debug("Getting OCSP token ...");
    if (this.dataLoader == null) {
      throw new TechnicalException("Data loader is null");
    }
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("Querying by DSS ID <{}>", certificateToken.getDSSIdAsString());
    }

    String accessLocation = getAccessLocation(certificateToken.getCertificate());
    try {
      return queryOCSPToken(accessLocation, certificateToken, issuerCertificateToken);

      // DSS ignores and silently consumes DSSException resulting with invalid signature without OCSP.
      // Must rethrow as other exception to stop the signing process - no OCSP, no signature.
      // Any OCSP query exception should stop the signing process.
    } catch (DSSException e) {
      throw new TechnicalException("OCSP request failed", e);

      // Attach common data to CertificateValidationException and rethrow
    } catch (CertificateValidationException e) {
      e.setServiceType(getOCSPType());
      e.setServiceUrl(accessLocation);
      throw e;
    }
  }

  /**
   * Returns SK OCSP source location.
   *
   * @param certificate
   * @return OCSP source location
   */
  public String getAccessLocation(X509Certificate certificate) {
    if (getConfiguration() != null) {
      return getConfiguration().getOcspSource();
    }
    return Constant.Test.OCSP_SOURCE;
  }

  /*
   * RESTRICTED METHODS
   */

  protected abstract ServiceType getOCSPType();

  protected abstract Extension createNonce(X509Certificate certificate);

  private OCSPToken queryOCSPToken(String accessLocation, CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
    CertificateID certificateID = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken, DigestAlgorithm.SHA1);
    Extension nonceExtension = createNonce(certificateToken.getCertificate());

    byte[] response = dataLoader.post(accessLocation, buildRequest(certificateID, nonceExtension));
    BasicOCSPResp ocspResponse = parseAndVerifyOCSPResponse(response, accessLocation);
    checkNonce(ocspResponse, nonceExtension);

    OCSPToken ocspToken = constructOCSPToken(ocspResponse, accessLocation, certificateToken, issuerCertificateToken);
    verifyOCSPToken(ocspToken);
    return ocspToken;
  }

  private byte[] buildRequest(final CertificateID certificateID, Extension nonceExtension) {
    try {
      LOGGER.debug("Building OCSP request ...");
      OCSPReqBuilder builder = new OCSPReqBuilder();
      builder.addRequest(certificateID);
      if (nonceExtension != null) {
        builder.setRequestExtensions(new Extensions(nonceExtension));
      }
      if (this.configuration.hasToBeOCSPRequestSigned()) {
        LOGGER.info("Using signed OCSP request ...");
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
      throw new TechnicalException("Failed to construct OCSP request", e);
    }
  }

  private BasicOCSPResp parseAndVerifyOCSPResponse(byte[] response, String accessLocation) {
    try {
      OCSPResp ocspResp = new OCSPResp(response);
      validateOCSPResponseStatus(ocspResp.getStatus(), accessLocation);
      BasicOCSPResp ocspResponse = (BasicOCSPResp) ocspResp.getResponseObject();
      verifyOCSPResponse(ocspResponse);
      return ocspResponse;
    } catch (OCSPException | IOException e) {
      throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL, "Failed to parse OCSP response", e);
    }
  }

  private void validateOCSPResponseStatus(int ocspResponseStatus, String serviceUrl) {
    if (ocspResponseStatus == OCSPResp.SUCCESSFUL) {
      return;
    }

    LOGGER.warn("OCSP service responded with unsuccessful status <{}>", ocspResponseStatus);
    switch (ocspResponseStatus) {
      case OCSPResp.MALFORMED_REQUEST:
        throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL, "OCSP request malformed");
      case OCSPResp.INTERNAL_ERROR:
        throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL, "OCSP service internal error");
      case OCSPResp.SIG_REQUIRED:
        throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL, "OCSP request not signed");
      case OCSPResp.TRY_LATER:
        throw new ServiceUnavailableException(serviceUrl, getOCSPType());
      case OCSPResp.UNAUTHORIZED:
        throw new ServiceAccessDeniedException(serviceUrl, getOCSPType());
      default:
        throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL, "OCSP service responded with unknown status <" + ocspResponseStatus + ">");
    }
  }

  private void verifyOCSPResponse(BasicOCSPResp response) throws IOException {
    List<X509CertificateHolder> holders = Arrays.asList(response.getCerts());
    if (CollectionUtils.isNotEmpty(holders)) {
      boolean hasOcspResponderCert = false;
      for (X509CertificateHolder holder : holders) {
        CertificateToken token = DSSUtils.loadCertificate(holder.getEncoded());
        if (isOcspResponderCertificate(token)) {
          hasOcspResponderCert = true;
        } else {
          continue;
        }
        verifyOcspResponderCertificate(token, response.getProducedAt());
        verifyOCSPResponseSignature(token, response);
      }
      if (!hasOcspResponderCert) {
        throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL,
                "None of the OCSP response certificates does have 'OCSPSigning' extended key usage");
      }
    } else {
      if (!this.configuration.isTest()) {
        LOGGER.warn("OCSP response signature will not be verified. No response certificates has been found");
      }
    }
  }

  protected boolean isOcspResponderCertificate(CertificateToken token) {
    try {
      return token.getCertificate().getExtendedKeyUsage() != null && token.getCertificate().getExtendedKeyUsage().contains(OID_OCSP_SIGNING);
    } catch (CertificateParsingException e) {
      throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL,
              String.format("Error on verifying 'OCSPSigning' extended key usage for OCSP response certificate <%s>", token.getDSSIdAsString()), e);
    }
  }

  protected void verifyOcspResponderCertificate(CertificateToken token, Date producedAt) {
    verifyValidityDate(token, producedAt);
    if (!configuration.getTSL().isTrusted(token)) {
      throw CertificateValidationException.of(CertificateValidationStatus.UNTRUSTED,
              String.format("OCSP response certificate <%s> match is not found in TSL", token.getDSSIdAsString()));
    }
    try {
      if (!token.getCertificate().getExtendedKeyUsage().contains(OID_OCSP_SIGNING)) {
        throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL,
                String.format("OCSP response certificate <%s> does not have 'OCSPSigning' extended key usage", token.getDSSIdAsString()));
      }
    } catch (CertificateParsingException e) {
      throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL,
              String.format("Error on verifying 'OCSPSigning' extended key usage for OCSP response certificate <%s>", token.getDSSIdAsString()), e);
    }
  }

  protected void verifyValidityDate(CertificateToken token, Date producedAt) {
    X509Certificate x509Certificate = token.getCertificate();
    if (x509Certificate.getNotAfter().before(producedAt)
            || x509Certificate.getNotBefore().after(producedAt)) {
      throw CertificateValidationException.of(CertificateValidationStatus.UNTRUSTED,
              String.format("OCSP response certificate <%s> is expired or not yet valid", token.getDSSIdAsString()));
    }
  }

  private void verifyOCSPResponseSignature(CertificateToken token, BasicOCSPResp ocspResponse) {
    boolean signatureValid;
    try {
      ContentVerifierProvider provider = new JcaContentVerifierProviderBuilder()
              .setProvider("BC")
              .build(new X509CertificateHolder(token.getEncoded()));
      signatureValid = ocspResponse.isSignatureValid(provider);
    } catch (Exception e) {
      throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL, "Failed to verify OCSP response signature", e);
    }

    if (!signatureValid) {
      throw CertificateValidationException.of(CertificateValidationStatus.UNTRUSTED, "OCSP response signature is invalid");
    }
  }

  protected DSSPrivateKeyEntry getOCSPAccessCertificatePrivateKey() throws IOException {
    Pkcs12SignatureToken signatureTokenConnection = new Pkcs12SignatureToken(
            this.configuration.getOCSPAccessCertificateFileName(), new KeyStore.PasswordProtection(this.configuration
            .getOCSPAccessCertificatePassword()));
    return signatureTokenConnection.getKeys().get(0);
  }

  protected void checkNonce(BasicOCSPResp response, Extension expectedNonceExtension) {
    Extension extension = response.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    DEROctetString expectedNonce = (DEROctetString) expectedNonceExtension.getExtnValue();
    DEROctetString receivedNonce = (DEROctetString) extension.getExtnValue();
    if (!receivedNonce.equals(expectedNonce)) {
      String errorMessage = String.format("The OCSP request was victim of the replay attack (nonce sent <%s>, nonce received <%s>)", expectedNonce, receivedNonce);
      throw CertificateValidationException.of(CertificateValidationStatus.UNTRUSTED, errorMessage);
    }
  }

  private OCSPToken constructOCSPToken(BasicOCSPResp ocspResponse, String accessLocation,
                                       CertificateToken subjectCert, CertificateToken issuerCert) {
    SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(ocspResponse, subjectCert, issuerCert);
    OCSPToken token = new OCSPToken(ocspResponse, latestSingleResponse, subjectCert, issuerCert);
    token.setSourceURL(accessLocation);
    return token;
  }

  private void verifyOCSPToken(OCSPToken token) {
    if (token == null || token.getThisUpdate() == null) {
      throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL, "OCSP response token is missing");
    }

    if (token.getStatus() != null) {
      LOGGER.debug("Certificate with DSS ID <{}> - status <{}>", token.getDSSIdAsString(), token.getStatus().name());
      if (CertificateStatus.REVOKED.equals(token.getStatus())) {
        throw CertificateValidationException.of(CertificateValidationStatus.REVOKED, "Certificate status is revoked");
      }
      if (CertificateStatus.UNKNOWN.equals(token.getStatus())) {
        throw CertificateValidationException.of(CertificateValidationStatus.UNKNOWN, "Certificate is unknown");
      }
    } else {
      if (token.getReason() != null) {
        LOGGER.debug("Certificate with DSS ID <{}> - reason <{}>", token.getDSSIdAsString(), token.getReason().name());
      }
      throw CertificateValidationException.of(CertificateValidationStatus.UNKNOWN, "Certificate is unknown");
    }
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
   * @return DataLoader
   */
  public DataLoader getDataLoader() {
    return dataLoader;
  }

  /**
   * Define data loader.
   *
   * @param dataLoader Data loader object to be used.
   */
  public void setDataLoader(DataLoader dataLoader) {
    this.dataLoader = dataLoader;
  }

}