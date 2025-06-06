/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Trusted List certificates
 */
public interface TSLCertificateSource extends CertificateSource {

  /**
   * This method allows to define (to add) any certificate as trusted.
   * <p/>
   * Use with caution: the default Trust Service Provider settings used in this method
   * may not correspond with the actual properties of this Trust Service, specified in
   * the official European Commission Trust List.
   * <p/>
   * This method uses a set of default settings to add a CA service issuing Qualified Certificates
   * to the library's trust store.
   * <p/>
   * ServiceName will be the certificate's CN field value <br/>
   * ServiceTypeIdentifier will be: <br/>
   *    http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC - if certificate contains "OCSPSigning" extended key usage <br/>
   *    http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST - if certificate contains "timeStamping" extended key usage
   *    http://uri.etsi.org/TrstSvc/Svctype/CA/QC - otherwise <br/>
   * Qualifier will be http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD with nonRepudiation <br/>
   * ServiceStatus will be: <br/>
   *    Certificate's NotBefore pre Eidas -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision <br/>
   *    Certificate's NotBefore post Eidas -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted <br/>
   * CountryCode will be EU <br/>
   * TLInfo for EU will be added automatically when it does not exist
   *
   * @param certificate X509 certificate to be added to the list, a certificate you have to trust.
   */
  void addTSLCertificate(X509Certificate certificate);

  /**
   * This method allows to define (to add) any certificate as trusted.
   * Service information is associated to this certificate.
   *
   * @param certificate
   *            the certificate you have to trust
   * @param trustProperties
   *            list of the service information associated to the service
   */
  void addCertificate(final CertificateToken certificate, final List<TrustProperties> trustProperties);

  /**
   * Returns a list of alternative OCSP access point Urls for certificates issued by the current trust anchor
   *
   * @param trustAnchor {@link CertificateToken}
   * @return a list of {@link String}s
   */
  List<String> getAlternativeOCSPUrls(CertificateToken trustAnchor);

  /**
   * Returns a list of alternative CRL access point Urls for certificates issued by the current trust anchor
   *
   * @param trustAnchor {@link CertificateToken}
   * @return a list of {@link String}s
   */
  List<String> getAlternativeCRLUrls(CertificateToken trustAnchor);

  /**
   * Retrieves the list of all certificate tokens from this source.
   *
   * @return all the TSL certificates.
   */
  List<CertificateToken> getCertificates();

  /**
   * Retrieves the list of trust properties for the gifen certificate token.
   *
   * @param token
   * @return all the Trust Properties associated with the certificate token.
   */
  List<TrustProperties> getTrustServices(CertificateToken token);

  /**
   * Returns trust time period for the given certificate, when the certificate is considered as a trust anchor.
   * For an unbounded period of trust time, returns a {@code CertificateTrustTime} with empty values.
   * When the certificate is not trusted at any time, returns not trusted {@code CertificateTrustTime} entry.
   *
   * @param token {@link CertificateToken}
   * @return {@link CertificateTrustTime}
   */
  CertificateTrustTime getTrustTime(CertificateToken token);

  /**
   * This method returns the number of stored certificates in this source
   *
   * @return number of certificates in this instance
   */
  int getNumberOfCertificates();

  /**
   * Gets TL Validation job summary
   *
   * @return {@link TLValidationJobSummary}
   */
  TLValidationJobSummary getSummary();

  /**
   * Gets the number of trusted entity keys (public key + subject name)
   *
   * @return the number of trusted entity keys (public key + subject name)
   */
  int getNumberOfTrustedEntityKeys();

  /**
   * @deprecated Deprecated for removal. Use {@link #getNumberOfTrustedEntityKeys()} instead.
   */
  @Deprecated
  default int getNumberOfTrustedPublicKeys() {
    return getNumberOfTrustedEntityKeys();
  }

  /**
   * Invalidates cache
   *
   * Only applicable when cache is used.
   *
   */
  void invalidateCache();

  void refresh();
}
