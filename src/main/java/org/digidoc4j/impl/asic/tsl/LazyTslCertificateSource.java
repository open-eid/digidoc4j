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

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Lazily initialized certificate source. It allows to initialize objects and populate parameters
 * where a certificate source is necessary, but is not yet accessed.
 *
 * The goal is to postpone initialization and downloading of TSL until it is really needed to speed up processes.
 * For example, it is not necessary to download TSL to open container and see signature parameters, but DSS library
 * requires the presence of certificate source. TSL should be downloaded for validation and other functionality where
 * it is really necessary to check the certificates.
 *
 * To achieve that, a lazily initialized certificate source is used.
 */
public class LazyTslCertificateSource implements TSLCertificateSource {

  private static final Logger logger = LoggerFactory.getLogger(LazyTslCertificateSource.class);
  private TSLCertificateSource certificateSource;
  private transient TSLValidationJob tslValidationJob;
  private Long lastCacheReloadingTime;
  private Long cacheExpirationTime;
  private TslLoader tslLoader;

  public LazyTslCertificateSource(TslLoader tslLoader) {
    logger.debug("Initializing lazy TSL certificate source");
    this.tslLoader = tslLoader;
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
  public void addTSLCertificate(X509Certificate certificate) {
    getCertificateSource().addTSLCertificate(certificate);
  }

  @Override
  public CertificateToken addCertificate(CertificateToken certificate, ServiceInfo serviceInfo) {
    return getCertificateSource().addCertificate(certificate, serviceInfo);
  }

  @Override
  public List<CertificateToken> getCertificates() {
    return getCertificateSource().getCertificates();
  }

  @Override
  public void invalidateCache() {
    logger.debug("Invalidating TSL cache");
    TslLoader.invalidateCache();
  }

  @Override
  public void refresh() {
    refreshTsl();
  }

  public void setCacheExpirationTime(Long cacheExpirationTime) {
    this.cacheExpirationTime = cacheExpirationTime;
  }

  protected void refreshIfCacheExpired() {
    if (isCacheExpired()) {
      initTsl();
    }
  }

  public Long getCacheExpirationTime() {
    return cacheExpirationTime;
  }

  public Long getLastCacheReloadingTime() {
    return lastCacheReloadingTime;
  }

  private TSLCertificateSource getCertificateSource() {
    logger.debug("Accessing TSL");
    refreshIfCacheExpired();
    return certificateSource;
  }

  private synchronized void initTsl() {
    //Using double-checked locking to avoid other threads to start loading TSL
    if (isCacheExpired()) {
      logger.debug("Initializing TSL");
      refreshTsl();
    }
  }

  private synchronized void refreshTsl() {
    try {
      populateTsl();
      logger.debug("Refreshing TSL");
      tslValidationJob.refresh();
      lastCacheReloadingTime = new Date().getTime();
      if (logger.isDebugEnabled()) {
        logger.debug("Finished refreshing TSL, cache expires at " + getNextCacheExpirationDate());
      }
    } catch (DSSException e) {
      logger.error("Unable to load TSL: " + e.getMessage());
      throw new TslCertificateSourceInitializationException(e.getMessage());
    }
  }

  private void populateTsl() {
    if (tslValidationJob == null || certificateSource == null) {
      tslLoader.prepareTsl();
      tslValidationJob = tslLoader.getTslValidationJob();
      certificateSource = tslLoader.getTslCertificateSource();
    }
  }

  private boolean isCacheExpired() {
    if (lastCacheReloadingTime == null) {
      return true;
    }
    long currentTime = new Date().getTime();
    long timeToReload = lastCacheReloadingTime + cacheExpirationTime;
    return currentTime > timeToReload;
  }

  private String getNextCacheExpirationDate() {
    return new Date(lastCacheReloadingTime + cacheExpirationTime).toString();
  }
}
