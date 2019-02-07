package org.digidoc4j;

import java.security.cert.X509Certificate;
import java.util.*;

import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TLInfo;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

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
   * ServiceName is the certificate's CN field value<br/>
   * ServiceTypeIdentifier is http://uri.etsi.org/TrstSvc/Svctype/CA/QC <br/>
   * Qualifier is http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD with nonRepudiation <br/>
   * ServiceStatus is: <br/>
   *    Certificate's NotBefore pre Eidas date -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision <br/>
   *    Certificate's NotBefore post Eidas date -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted <br/>
   * CountryCode is EU <br/>
   *
   * @param certificate X509 certificate to be added to the list, a certificate you have to trust.
   */
  void addTSLCertificate(X509Certificate certificate);

  /**
   * This method allows to define (to add) any certificate as trusted. A
   * service information is associated to this certificate.
   *
   * @param certificate
   *            the certificate you have to trust
   * @param serviceInfos
   *            list of the service information associated to the service
   * @return the corresponding certificate token
   */
  void addCertificate(final CertificateToken certificate, final List<ServiceInfo> serviceInfos);

  /**
   * Retrieves the list of all certificate tokens from this source.
   *
   * @return all the TSL certificates.
   */
  List<CertificateToken> getCertificates();

  /**
   * Retrieves the list of service infos for the gifen certificate token.
   *
   * @param token
   * @return all the Service Infos associated with the certificate token.
   */
  Set<ServiceInfo> getTrustServices(CertificateToken token);

  /**
   * This method returns the number of stored certificates in this source
   *
   * @return number of certificates in this instance
   */
  int getNumberOfCertificates();

  TLInfo getLotlInfo();

  TLInfo getTlInfo(String countryCode);

  Map<String, TLInfo> getSummary();

  int getNumberOfTrustedPublicKeys();

  /**
   * Invalidates cache
   *
   * Only applicable when cache is used.
   *
   */
  void invalidateCache();

  void refresh();
}
