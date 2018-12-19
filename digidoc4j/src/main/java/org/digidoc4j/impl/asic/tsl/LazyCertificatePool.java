/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.tsl;

import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Lazily initialized certificate pool. It allows to initialize objects and populate parameters
 * where a certificate pool is necessary, but is not yet accessed.
 *
 * The goal is to postpone initialization and downloading of TSL until it is really needed to speed up processes.
 * For example, it is not necessary to download TSL to open container and see signature parameters, but DSS library
 * requires the presence of certificate pool. TSL should be downloaded for validation and other functionality where
 * it is really necessary to check the certificates.
 *
 * To achieve that, a lazily initialized certificate pool is used.
 */
public class LazyCertificatePool extends CertificatePool {

  private static final Logger logger = LoggerFactory.getLogger(LazyCertificatePool.class);

  private CertificateSource trustedCertSource;

  public LazyCertificatePool(CertificateSource trustedCertSource) {
    logger.debug("Initializing lazy certificate pool");
    this.trustedCertSource = trustedCertSource;
  }

  @Override
  public List<CertificateToken> get(X500Principal x500Principal) {
    return getCertificatePool().get(x500Principal);
  }

  @Override
  public List<CertificateToken> getCertificateTokens() {
    return getCertificatePool().getCertificateTokens();
  }

  @Override
  public CertificateToken getInstance(CertificateToken cert, CertificateSourceType certSource) {
    return getCertificatePool().getInstance(cert, certSource);
  }

  @Override
  public CertificateToken getInstance(CertificateToken cert, CertificateSourceType certSource, ServiceInfo serviceInfo) {
    return getCertificatePool().getInstance(cert, certSource, serviceInfo);
  }

  @Override
  public CertificateToken getInstance(CertificateToken certificateToAdd, Set<CertificateSourceType> sources, Set<ServiceInfo> services) {
    return getCertificatePool().getInstance(certificateToAdd, sources, services);
  }

  @Override
  public int getNumberOfCertificates() {
    return getCertificatePool().getNumberOfCertificates();
  }

  @Override
  public void merge(CertificatePool certPool) {
    getCertificatePool().merge(certPool);
  }

  private CertificatePool getCertificatePool() {
    logger.debug("Accessing certificate pool");
    return trustedCertSource.getCertificatePool();
  }
}
