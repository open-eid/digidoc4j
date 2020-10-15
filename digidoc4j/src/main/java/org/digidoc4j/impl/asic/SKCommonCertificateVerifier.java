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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.ListRevocationSource;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Delegate class for SD-DSS CommonCertificateVerifier. Needed for making serialization possible
 */
public class SKCommonCertificateVerifier implements Serializable, CertificateVerifier {

  private transient CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
  private transient CertificateSource trustedCertSource;

  public SKCommonCertificateVerifier() {
    this.commonCertificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
  }

  @Override
  public void setTrustedCertSource(final CertificateSource trustedCertSource) {
    this.trustedCertSource = trustedCertSource;
    this.commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
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
  public ListCertificateSource getTrustedCertSources() {
    return this.commonCertificateVerifier.getTrustedCertSources();
  }

  @Override
  public void setAdjunctCertSource(final CertificateSource adjunctCertSource) {
    this.commonCertificateVerifier.setAdjunctCertSource(adjunctCertSource);
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
  public DataLoader getDataLoader() {
    return this.commonCertificateVerifier.getDataLoader();
  }

  @Override
  public void setDataLoader(final DataLoader dataLoader) {
    this.commonCertificateVerifier.setDataLoader(dataLoader);
  }

  @Override
  public ListRevocationSource<CRL> getSignatureCRLSource() {
    return this.commonCertificateVerifier.getSignatureCRLSource();
  }

  @Override
  public void setSignatureCRLSource(ListRevocationSource<CRL> signatureCRLSource) {
    this.commonCertificateVerifier.setSignatureCRLSource(signatureCRLSource);
  }

  @Override
  public ListRevocationSource<OCSP> getSignatureOCSPSource() {
    return this.commonCertificateVerifier.getSignatureOCSPSource();
  }

  @Override
  public void setSignatureOCSPSource(ListRevocationSource<OCSP> signatureOCSPSource) {
    this.commonCertificateVerifier.setSignatureOCSPSource(signatureOCSPSource);
  }

  @Override
  public ListCertificateSource getSignatureCertificateSource() {
    return this.commonCertificateVerifier.getSignatureCertificateSource();
  }

  @Override
  public void setSignatureCertificateSource(ListCertificateSource signatureCertificateSource) {
    this.commonCertificateVerifier.setSignatureCertificateSource(signatureCertificateSource);
  }

  @Override
  public void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    this.commonCertificateVerifier.setDefaultDigestAlgorithm(digestAlgorithm);
  }

  @Override
  public DigestAlgorithm getDefaultDigestAlgorithm() {
    return this.commonCertificateVerifier.getDefaultDigestAlgorithm();
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
