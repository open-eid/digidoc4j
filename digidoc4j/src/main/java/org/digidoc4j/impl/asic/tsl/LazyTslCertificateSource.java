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
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustPropertiesCertificateSource;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSourceEntity;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
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
public class LazyTslCertificateSource implements TSLCertificateSource, TrustedCertificateSource, TrustPropertiesCertificateSource {

  private static final Logger LOGGER = LoggerFactory.getLogger(LazyTslCertificateSource.class);

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
  public CertificateToken addCertificate(CertificateToken certificate) {
    return getCertificateSource().addCertificate(certificate);
  }

  @Override
  public void addCertificate(CertificateToken certificate, List<TrustProperties> trustProperties) {
    getCertificateSource().addCertificate(certificate, trustProperties);
  }

  @Override
  public void addTSLCertificate(X509Certificate certificate) {
    getCertificateSource().addTSLCertificate(certificate);
  }

  @Override
  public Set<CertificateToken> findTokensFromCertRef(CertificateRef certificateRef) {
    return getCertificateSource().findTokensFromCertRef(certificateRef);
  }

  @Override
  public List<String> getAlternativeOCSPUrls(CertificateToken certificateToken) {
    return getCertificateSource().getAlternativeOCSPUrls(certificateToken);
  }

  @Override
  public List<String> getAlternativeCRLUrls(CertificateToken certificateToken) {
    return getCertificateSource().getAlternativeCRLUrls(certificateToken);
  }

  @Override
  public Set<CertificateToken> getByEntityKey(EntityIdentifier entityIdentifier) {
    return getCertificateSource().getByEntityKey(entityIdentifier);
  }

  @Override
  public Set<CertificateToken> getByCertificateDigest(Digest digest) {
    return getCertificateSource().getByCertificateDigest(digest);
  }

  @Override
  public Set<CertificateToken> getByPublicKey(PublicKey publicKey) {
    return getCertificateSource().getByPublicKey(publicKey);
  }

  @Override
  public Set<CertificateToken> getBySignerIdentifier(SignerIdentifier signerIdentifier) {
    return getCertificateSource().getBySignerIdentifier(signerIdentifier);
  }

  @Override
  public Set<CertificateToken> getBySki(byte[] bytes) {
    return getCertificateSource().getBySki(bytes);
  }

  @Override
  public Set<CertificateToken> getBySubject(X500PrincipalHelper subject) {
    return getCertificateSource().getBySubject(subject);
  }

  @Override
  public List<CertificateToken> getCertificates() {
    return getCertificateSource().getCertificates();
  }

  @Override
  public CertificateSourceType getCertificateSourceType() {
    // Do not invoke lazy loading, expect the source to always be trusted list
    return CertificateSourceType.TRUSTED_LIST;
  }

  @Override
  public List<CertificateSourceEntity> getEntities() {
    return getCertificateSource().getEntities();
  }

  @Override
  public int getNumberOfCertificates() {
    return getCertificateSource().getNumberOfCertificates();
  }

  @Override
  public int getNumberOfTrustedEntityKeys() {
    return getCertificateSource().getNumberOfTrustedEntityKeys();
  }

  @Override
  public TLValidationJobSummary getSummary() {
    return getCertificateSource().getSummary();
  }

  @Override
  public List<TrustProperties> getTrustServices(CertificateToken token) {
    return getCertificateSource().getTrustServices(token);
  }

  @Override
  public CertificateTrustTime getTrustTime(CertificateToken certificateToken) {
    return getCertificateSource().getTrustTime(certificateToken);
  }

  @Override
  public boolean isAllSelfSigned() {
    return getCertificateSource().isAllSelfSigned();
  }

  @Override
  public boolean isCertificateSourceEqual(CertificateSource certificateSource) {
    return getCertificateSource().isCertificateSourceEqual(certificateSource);
  }

  @Override
  public boolean isCertificateSourceEquivalent(CertificateSource certificateSource) {
    return getCertificateSource().isCertificateSourceEquivalent(certificateSource);
  }

  @Override
  public boolean isKnown(CertificateToken token) {
    return getCertificateSource().isKnown(token);
  }

  @Override
  public boolean isTrusted(CertificateToken certificateToken) {
    return getCertificateSource().isTrusted(certificateToken);
  }

  @Override
  public boolean isTrustedAtTime(CertificateToken certificateToken, Date date) {
    return getCertificateSource().isTrustedAtTime(certificateToken, date);
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

  @Override
  public void setSummary(TLValidationJobSummary tlValidationJobSummary) {
    throw new UnsupportedOperationException("Overwriting summary is not supported for lay TSL certificate source");
  }

  @Override
  public void setTrustPropertiesByCertificates(Map<CertificateToken, List<TrustProperties>> map) {
    throw new UnsupportedOperationException("Adding trust properties mappings is not supported for lay TSL certificate source");
  }

  @Override
  public void setTrustTimeByCertificates(Map<CertificateToken, List<CertificateTrustTime>> map) {
    throw new UnsupportedOperationException("Adding trust time mappings is not supported for lay TSL certificate source");
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
      this.lastCacheReloadingTime = null;
      if (tslLoader.getTslRefreshCallback().ensureTSLState(tlValidationJob.getSummary())) {
        this.lastCacheReloadingTime = new Date().getTime();
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Finished refreshing TSL, cache expires at {}", this.getNextCacheExpirationDate());
        }
      } else {
        LOGGER.debug("Finished refreshing TSL, cache is still expired");
      }
    } catch (DSSException e) {
      throw new TslCertificateSourceInitializationException("Failed to initialize TSL: " + e.getMessage(), e);
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
