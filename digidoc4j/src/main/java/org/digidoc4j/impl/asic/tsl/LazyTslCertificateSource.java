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

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Lazily initialized certificate source. It allows to initialize objects and populate parameters
 * where a certificate source is necessary, but is not yet accessed.
 * <p>
 * The goal is to postpone initialization and downloading of TSL until it is really needed to speed up processes.
 * For example, it is not necessary to download TSL to open container and see signature parameters, but DSS library
 * requires the presence of certificate source. TSL should be downloaded for validation and other functionality where
 * it is really necessary to check the certificates.
 * <p>
 * To achieve that, a lazily initialized certificate source is used.
 */
public class LazyTslCertificateSource extends TrustedListsCertificateSource implements TSLCertificateSource {

  private static final Logger LOGGER = LoggerFactory.getLogger(LazyTslCertificateSource.class);
  private static final String CACHE_ERROR_STATUS = "ERROR";
  private transient TLValidationJob tlValidationJob;
  private TSLCertificateSource certificateSource;
  private Long lastCacheReloadingTime;
  private Long cacheExpirationTime;
  private final TslLoader tslLoader;

  /**
   * @param tslLoader TSL loader
   */
  public LazyTslCertificateSource(TslLoader tslLoader) {
    LOGGER.debug("Initializing lazy TSL certificate source");
    this.tslLoader = tslLoader;
  }

  @Override
  public TLValidationJobSummary getSummary() {
    return this.getCertificateSource().getSummary();
  }

  @Override
  public int getNumberOfCertificates() {
    return this.getCertificateSource().getNumberOfCertificates();
  }

  @Override
  public CertificateToken addCertificate(CertificateToken certificate) {
    return this.getCertificateSource().addCertificate(certificate);
  }

  @Override
  public boolean isKnown(CertificateToken token) {
    return this.getCertificateSource().isKnown(token);
  }

  @Override
  public List<TrustProperties> getTrustServices(CertificateToken token) {
    return this.getCertificateSource().getTrustServices(token);
  }

  @Override
  public CertificateSourceType getCertificateSourceType() {
    return CertificateSourceType.TRUSTED_LIST;
  }

  @Override
  public void addTSLCertificate(X509Certificate certificate) {
    this.getCertificateSource().addTSLCertificate(certificate);
  }

  @Override
  public Set<CertificateToken> getBySubject(X500PrincipalHelper subject) {
    return this.getCertificateSource().getBySubject(subject);
  }

  @Override
  public Set<CertificateToken> getByPublicKey(PublicKey publicKey) {
    return this.getCertificateSource().getByPublicKey(publicKey);
  }

  @Override
  public List<CertificateToken> getCertificates() {
    return this.getCertificateSource().getCertificates();
  }

  @Override
  public boolean isTrusted(CertificateToken certificateToken) {
    return isKnown(certificateToken);
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

  protected TSLCertificateSource getCertificateSource() {
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
      this.tlValidationJob.onlineRefresh();
      this.validateLotlLoading();
      this.lastCacheReloadingTime = new Date().getTime();
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Finished refreshing TSL, cache expires at {}", this.getNextCacheExpirationDate());
      }
    } catch (DSSException e) {
      throw new TslCertificateSourceInitializationException("Failed to initialize TSL: " + e.getMessage(), e);
    }
  }

  private void validateLotlLoading() {
    for (LOTLInfo info : certificateSource.getSummary().getLOTLInfos()) {
      if (CACHE_ERROR_STATUS.equals(info.getDownloadCacheInfo().getStatusName())
              || !info.getParsingCacheInfo().isResultExist()) {
        throw new TslCertificateSourceInitializationException("Failed to initialize TSL");
      }
    }
  }

  private void populateTsl() {
    if (this.tlValidationJob == null || this.certificateSource == null) {
      this.tslLoader.prepareTsl();
      this.tlValidationJob = this.tslLoader.getTlValidationJob();
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

  public TslLoader getTslLoader() {
    return tslLoader;
  }
}
