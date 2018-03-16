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

  private static final Logger LOGGER = LoggerFactory.getLogger(LazyTslCertificateSource.class);
  private transient TSLValidationJob tslValidationJob;
  private TSLCertificateSource certificateSource;
  private Long lastCacheReloadingTime;
  private Long cacheExpirationTime;
  private TslLoader tslLoader;

  /**
   * @param tslLoader TSL loader
   */
  public LazyTslCertificateSource(TslLoader tslLoader) {
    LOGGER.debug("Initializing lazy TSL certificate source");
    this.tslLoader = tslLoader;
  }

  @Override
  public CertificatePool getCertificatePool() {
    return this.getCertificateSource().getCertificatePool();
  }

  @Override
  public CertificateToken addCertificate(CertificateToken certificate) {
    return this.getCertificateSource().addCertificate(certificate);
  }

  @Override
  public List<CertificateToken> get(X500Principal x500Principal) {
    return this.getCertificateSource().get(x500Principal);
  }

  @Override
  public void addTSLCertificate(X509Certificate certificate) {
    this.getCertificateSource().addTSLCertificate(certificate);
  }

  @Override
  public CertificateToken addCertificate(CertificateToken certificate, ServiceInfo serviceInfo) {
    return this.getCertificateSource().addCertificate(certificate, serviceInfo);
  }

  @Override
  public List<CertificateToken> getCertificates() {
    return this.getCertificateSource().getCertificates();
  }

  @Override
  public void invalidateCache() {
    LOGGER.debug("Invalidating TSL cache");
    TslLoader.invalidateCache();
  }

  @Override
  public void refresh() {
    this.refreshTsl();
  }

  /*
   * RESTRICTED METHODS
   */

  protected void refreshIfCacheExpired() {
    if (this.isCacheExpired()) {
      this.initTsl();
    }
  }

  private TSLCertificateSource getCertificateSource() {
    LOGGER.debug("Accessing TSL");
    this.refreshIfCacheExpired();
    return this.certificateSource;
  }

  private synchronized void initTsl() {
    //Using double-checked locking to avoid other threads to start loading TSL
    if (this.isCacheExpired()) {
      LOGGER.debug("Initializing TSL");
      this.refreshTsl();
    }
  }

  private synchronized void refreshTsl() {
    try {
      this.populateTsl();
      LOGGER.debug("Refreshing TSL");
      this.tslValidationJob.refresh();
      this.lastCacheReloadingTime = new Date().getTime();
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Finished refreshing TSL, cache expires at {}", this.getNextCacheExpirationDate());
      }
    } catch (DSSException e) {
      throw new TslCertificateSourceInitializationException("Unable to load TSL", e);
    }
  }

  private void populateTsl() {
    if (this.tslValidationJob == null || this.certificateSource == null) {
      this.tslLoader.prepareTsl();
      this.tslValidationJob = this.tslLoader.getTslValidationJob();
      this.certificateSource = this.tslLoader.getTslCertificateSource();
    }
  }

  private boolean isCacheExpired() {
    if (this.lastCacheReloadingTime == null) {
      return true;
    }
    long currentTime = new Date().getTime();
    long timeToReload = this.lastCacheReloadingTime + this.cacheExpirationTime;
    return currentTime > timeToReload;
  }

  private String getNextCacheExpirationDate() {
    return new Date(this.lastCacheReloadingTime + this.cacheExpirationTime).toString();
  }

  /*
   * ACCESSORS
   */

  public Long getLastCacheReloadingTime() {
    return lastCacheReloadingTime;
  }

  public Long getCacheExpirationTime() {
    return cacheExpirationTime;
  }

  public void setCacheExpirationTime(Long cacheExpirationTime) {
    this.cacheExpirationTime = cacheExpirationTime;
  }

  public TslLoader getTslLoader(){
    return tslLoader;
  }

}
