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

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.x509.CertificateSourceType;
import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Uses a cloned TSL object so that each signature creation and validation process would
 * use its own separate TSL object. This avoids polluting certificate pool with certificates
 * found within signatures.
 */
public class ClonedTslCertificateSource implements CertificateSource {

  private static final Logger logger = LoggerFactory.getLogger(ClonedTslCertificateSource.class);
  private CertificateSource certificateSource;
  private CertificateSource clonedCertificateSource;
  private TrustedListsCertificateSource trustedListsCertificateSource;

  /**
   * @param certificateSource source of certificate
   */
  public ClonedTslCertificateSource(CertificateSource certificateSource) {
    logger.debug("Instantiating cloned tsl cert source");
    this.certificateSource = certificateSource;
  }

  private CertificateSource getCertificateSource() {
    logger.debug("Accessing TSL");
    if (clonedCertificateSource == null) {
      initializeClonedTsl();
    }
    return clonedCertificateSource;
  }

  private void initializeClonedTsl() {
    if (certificateSource instanceof LazyTslCertificateSource) {
      ((LazyTslCertificateSource) certificateSource).refreshIfCacheExpired();
      trustedListsCertificateSource = ((LazyTslCertificateSource) certificateSource).getTslLoader().getTslCertificateSource();
    }
    logger.debug("Cloning TSL");
    clonedCertificateSource = (CertificateSource) SerializationUtils.clone(certificateSource);
    logger.debug("Finished cloning TSL");
  }

  /**
   * Get TrustedListsCertificateSource object defined in TslLoader.
   *
   * @return TrustedListsCertificateSource
   */
  public TrustedListsCertificateSource getTrustedListsCertificateSource(){
    return trustedListsCertificateSource;
  }

  @Override
  public CertificatePool getCertificatePool() {
    return getCertificateSource().getCertificatePool();
  }

  @Override
  public CertificateToken addCertificate(CertificateToken certificate) {
    return getCertificateSource().addCertificate(certificate);
  }

  @Override
  public List<CertificateToken> get(X500Principal x500Principal) {
    return getCertificateSource().get(x500Principal);
  }

  @Override
  public CertificateSourceType getCertificateSourceType() {
    return CertificateSourceType.TRUSTED_LIST;
  }

  @Override
  public List<CertificateToken> getCertificates() {
    return getCertificateSource().getCertificates();
  }
}
