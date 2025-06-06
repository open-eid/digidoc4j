/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.RevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;
import eu.europa.esig.dss.spi.validation.TimestampTokenVerifier;
import eu.europa.esig.dss.spi.validation.TrustAnchorVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Delegate class for SD-DSS CommonCertificateVerifier. Needed for making serialization possible
 */
public class SKCommonCertificateVerifier implements Serializable, CertificateVerifier {

  private transient CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

  public SKCommonCertificateVerifier() {
    this.commonCertificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
  }

  @Override
  public void setTrustedCertSources(CertificateSource... certSources) {
    this.commonCertificateVerifier.setTrustedCertSources(certSources);
  }

  @Override
  public void addTrustedCertSources(CertificateSource... certSources) {
    this.commonCertificateVerifier.addTrustedCertSources(certSources);
  }

  @Override
  public void setTrustedCertSources(ListCertificateSource trustedListCertificateSource) {
    this.commonCertificateVerifier.setTrustedCertSources(trustedListCertificateSource);
  }

  @Override
  public ListCertificateSource getAdjunctCertSources() {
    return this.commonCertificateVerifier.getAdjunctCertSources();
  }

  @Override
  public RevocationSource<OCSP> getOcspSource() {
    return this.commonCertificateVerifier.getOcspSource();
  }

  @Override
  public RevocationSource<CRL> getCrlSource() {
    return this.commonCertificateVerifier.getCrlSource();
  }

  @Override
  public void setCrlSource(RevocationSource<CRL> crlSource) {
    this.commonCertificateVerifier.setCrlSource(crlSource);
  }

  @Override
  public void setOcspSource(RevocationSource<OCSP> ocspSource) {
    this.commonCertificateVerifier.setOcspSource(ocspSource);
  }

  @Override
  public RevocationDataLoadingStrategyFactory getRevocationDataLoadingStrategyFactory() {
    return this.commonCertificateVerifier.getRevocationDataLoadingStrategyFactory();
  }

  @Override
  public void setRevocationDataLoadingStrategyFactory(RevocationDataLoadingStrategyFactory revocationDataLoadingStrategyFactory) {
    this.commonCertificateVerifier.setRevocationDataLoadingStrategyFactory(revocationDataLoadingStrategyFactory);
  }

  @Override
  public RevocationDataVerifier getRevocationDataVerifier() {
    return this.commonCertificateVerifier.getRevocationDataVerifier();
  }

  @Override
  public void setRevocationDataVerifier(RevocationDataVerifier revocationDataVerifier) {
    this.commonCertificateVerifier.setRevocationDataVerifier(revocationDataVerifier);
  }

  @Override
  public boolean isRevocationFallback() {
    return this.commonCertificateVerifier.isRevocationFallback();
  }

  @Override
  public void setRevocationFallback(boolean isRevocationFallback) {
    this.commonCertificateVerifier.setRevocationFallback(isRevocationFallback);
  }

  @Override
  public TimestampTokenVerifier getTimestampTokenVerifier() {
    return commonCertificateVerifier.getTimestampTokenVerifier();
  }

  @Override
  public void setTimestampTokenVerifier(TimestampTokenVerifier timestampTokenVerifier) {
    commonCertificateVerifier.setTimestampTokenVerifier(timestampTokenVerifier);
  }

  @Override
  public TrustAnchorVerifier getTrustAnchorVerifier() {
    return commonCertificateVerifier.getTrustAnchorVerifier();
  }

  @Override
  public void setTrustAnchorVerifier(TrustAnchorVerifier trustAnchorVerifier) {
    commonCertificateVerifier.setTrustAnchorVerifier(trustAnchorVerifier);
  }

  @Override
  public ListCertificateSource getTrustedCertSources() {
    return this.commonCertificateVerifier.getTrustedCertSources();
  }

  @Override
  public void setAdjunctCertSources(CertificateSource... certSources) {
    this.commonCertificateVerifier.setAdjunctCertSources(certSources);
  }

  @Override
  public void addAdjunctCertSources(CertificateSource... certSources) {
    this.commonCertificateVerifier.addAdjunctCertSources(certSources);
  }

  @Override
  public void setAdjunctCertSources(ListCertificateSource adjunctListCertificateSource) {
    this.commonCertificateVerifier.setAdjunctCertSources(adjunctListCertificateSource);
  }

  @Override
  public AIASource getAIASource() {
    return this.commonCertificateVerifier.getAIASource();
  }

  @Override
  public void setAIASource(AIASource aiaSource) {
    this.commonCertificateVerifier.setAIASource(aiaSource);
  }

  @Override
  public void setAlertOnInvalidSignature(StatusAlert statusAlert) {
    commonCertificateVerifier.setAlertOnInvalidSignature(statusAlert);
  }

  @Override
  public StatusAlert getAlertOnInvalidSignature() {
    return commonCertificateVerifier.getAlertOnInvalidSignature();
  }

  @Override
  public void setAlertOnInvalidTimestamp(StatusAlert alertOnInvalidTimestamp) {
    this.commonCertificateVerifier.setAlertOnInvalidTimestamp(alertOnInvalidTimestamp);
  }

  @Override
  public StatusAlert getAlertOnInvalidTimestamp() {
    return this.commonCertificateVerifier.getAlertOnInvalidTimestamp();
  }

  @Override
  public void setAlertOnMissingRevocationData(StatusAlert alertOnMissingRevocationData) {
    this.commonCertificateVerifier.setAlertOnMissingRevocationData(alertOnMissingRevocationData);
  }

  @Override
  public StatusAlert getAlertOnMissingRevocationData() {
    return this.commonCertificateVerifier.getAlertOnMissingRevocationData();
  }

  @Override
  public void setAlertOnRevokedCertificate(StatusAlert alertOnRevokedCertificate) {
    this.commonCertificateVerifier.setAlertOnRevokedCertificate(alertOnRevokedCertificate);
  }

  @Override
  public StatusAlert getAlertOnRevokedCertificate() {
    return this.commonCertificateVerifier.getAlertOnRevokedCertificate();
  }

  @Override
  public void setAlertOnNoRevocationAfterBestSignatureTime(StatusAlert alertOnNoRevocationAfterBestSignatureTime) {
    this.commonCertificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(alertOnNoRevocationAfterBestSignatureTime);
  }

  @Override
  public StatusAlert getAlertOnNoRevocationAfterBestSignatureTime() {
    return this.commonCertificateVerifier.getAlertOnNoRevocationAfterBestSignatureTime();
  }

  @Override
  public void setAlertOnUncoveredPOE(StatusAlert alertOnUncoveredPOE) {
    this.commonCertificateVerifier.setAlertOnUncoveredPOE(alertOnUncoveredPOE);
  }

  @Override
  public StatusAlert getAlertOnUncoveredPOE() {
    return this.commonCertificateVerifier.getAlertOnUncoveredPOE();
  }

  @Override
  public void setAlertOnExpiredCertificate(StatusAlert statusAlert) {
    commonCertificateVerifier.setAlertOnExpiredCertificate(statusAlert);
  }

  @Override
  public StatusAlert getAlertOnExpiredCertificate() {
    return commonCertificateVerifier.getAlertOnExpiredCertificate();
  }

  @Override
  public void setAlertOnNotYetValidCertificate(StatusAlert statusAlert) {
    commonCertificateVerifier.setAlertOnNotYetValidCertificate(statusAlert);
  }

  @Override
  public StatusAlert getAlertOnNotYetValidCertificate() {
    return commonCertificateVerifier.getAlertOnNotYetValidCertificate();
  }

  @Override
  public void setAugmentationAlertOnHigherSignatureLevel(StatusAlert statusAlert) {
    commonCertificateVerifier.setAugmentationAlertOnHigherSignatureLevel(statusAlert);
  }

  @Override
  public StatusAlert getAugmentationAlertOnHigherSignatureLevel() {
    return commonCertificateVerifier.getAugmentationAlertOnHigherSignatureLevel();
  }

  @Override
  public void setAugmentationAlertOnSignatureWithoutCertificates(StatusAlert statusAlert) {
    commonCertificateVerifier.setAugmentationAlertOnSignatureWithoutCertificates(statusAlert);
  }

  @Override
  public StatusAlert getAugmentationAlertOnSignatureWithoutCertificates() {
    return commonCertificateVerifier.getAugmentationAlertOnSignatureWithoutCertificates();
  }

  @Override
  public void setAugmentationAlertOnSelfSignedCertificateChains(StatusAlert statusAlert) {
    commonCertificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(statusAlert);
  }

  @Override
  public StatusAlert getAugmentationAlertOnSelfSignedCertificateChains() {
    return commonCertificateVerifier.getAugmentationAlertOnSelfSignedCertificateChains();
  }

  @Override
  public boolean isCheckRevocationForUntrustedChains() {
    return this.commonCertificateVerifier.isCheckRevocationForUntrustedChains();
  }

  @Override
  public void setCheckRevocationForUntrustedChains(boolean checkRevocationForUntrustedChains) {
    this.commonCertificateVerifier.setCheckRevocationForUntrustedChains(checkRevocationForUntrustedChains);
  }


  /*
   * RESTRICTED METHODS
   */

  private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    stream.defaultReadObject();
    this.commonCertificateVerifier = new CommonCertificateVerifier();
  }

}
