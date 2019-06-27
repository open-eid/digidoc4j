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

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.CertificateValidator;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.CertificateValidationException;
import org.digidoc4j.exceptions.CertificateValidationException.CertificateValidationStatus;
import org.digidoc4j.exceptions.NetworkException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Implementation class for validating certificates by using OCSP requests
 * <p>
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class OCSPCertificateValidator implements CertificateValidator {

  private static final Logger LOGGER = LoggerFactory.getLogger(OCSPCertificateValidator.class);
  private final Configuration configuration;
  private final CertificateSource certificateSource;
  private final OCSPSource ocspSource;

  /**
   * @param configuration     configuration context
   * @param certificateSource the source of certificates
   * @param ocspSource        the source of OCSP
   */
  public OCSPCertificateValidator(Configuration configuration, CertificateSource certificateSource, OCSPSource
      ocspSource) {
    this.configuration = configuration;
    this.certificateSource = certificateSource;
    this.ocspSource = ocspSource;
  }

  @Override
  public void validate(X509Certificate subjectCertificate) throws CertificateValidationException {
    try {
      if (subjectCertificate == null) {
        throw new IllegalArgumentException("Subject certificate is not provided");
      }
      CertificateToken issuerCertificateToken = this.getIssuerCertificateToken(subjectCertificate);
      this.ocspSource.getRevocationToken(new CertificateToken(subjectCertificate), issuerCertificateToken);
    } catch (CertificateValidationException | NetworkException e) {
      throw e;
    } catch (Exception e) {
      throw CertificateValidationException.of(CertificateValidationStatus.TECHNICAL, "OCSP validation failed", e);
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private CertificateToken getIssuerCertificateToken(X509Certificate certificate) throws CertificateEncodingException {
    CertificateToken certificateToken = null;
    try {
      certificateToken = DSSUtils.loadCertificate(certificate.getEncoded());
      if (certificateToken.getIssuerX500Principal() != null) {
        return this.getFromCertificateSource(certificateToken.getIssuerX500Principal());
      }
    } catch (IllegalStateException e) {
      LOGGER.warn("Certificate with DSS ID <{}> is untrusted. Not all the intermediate certificates added into OCSP" +
              " certificate source?",
          (certificateToken == null) ? certificate.getSubjectX500Principal().getName() : certificateToken
              .getDSSIdAsString(), e);
    }
    throw CertificateValidationException.of(CertificateValidationStatus.UNTRUSTED,
            "Failed to parse issuer certificate token. Not all intermediate certificates added into OCSP.");
  }

  private CertificateToken getFromCertificateSource(X500Principal principal) {
    List<CertificateToken> tokens = this.getCertificateTokens(principal);
    if (tokens.size() != 1) {
      throw new IllegalStateException(String.format("<%s> matching certificate tokens found from certificate source",
          tokens.size()));
    }
    return tokens.get(0);
  }

  private List<CertificateToken> getCertificateTokens(X500Principal principal) {
    List<CertificateToken> tokens = this.configuration.getTSL().get(principal);
    if (CollectionUtils.isEmpty(tokens)) {
      tokens = this.certificateSource.get(principal);
    }
    return tokens;
  }

  /*
   * ACCESSORS
   */

  @Override
  public CertificateSource getCertificateSource() {
    return certificateSource;
  }

}
