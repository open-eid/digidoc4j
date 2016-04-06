package org.digidoc4j;

import java.security.cert.X509Certificate;
import java.util.List;

import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Trusted List certificates
 */
public interface TSLCertificateSource extends CertificateSource {

  /**
   * This method allows to define (to add) any certificate as trusted.
   * <p/>
   * ServiceTypeIdentifier is http://uri.etsi.org/TrstSvc/Svctype/CA/QC
   * ServiceStatus is http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision
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
   * @param serviceInfo
   *            the service information associated to the service
   * @return the corresponding certificate token
   */
  CertificateToken addCertificate(final CertificateToken certificate, final ServiceInfo serviceInfo);

  /**
   * Retrieves the list of all certificate tokens from this source.
   *
   * @return all the TSL certificates.
   */
  List<CertificateToken> getCertificates();

  /**
   * Invalidates cache
   *
   * Only applicable when cache is used.
   *
   */
  void invalidateCache();

  void refresh();
}
