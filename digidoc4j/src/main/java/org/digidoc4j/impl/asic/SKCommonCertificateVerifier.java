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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.digidoc4j.impl.asic.tsl.CompoundCertificatePool;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.validation.ListCRLSource;
import eu.europa.esig.dss.validation.ListOCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;

/**
 * Delegate class for SD-DSS CommonCertificateVerifier. Needed for making serialization possible
 */
public class SKCommonCertificateVerifier implements Serializable, CertificateVerifier {

  private transient CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
  private transient CertificateSource trustedCertSource;

  public SKCommonCertificateVerifier() {
    commonCertificateVerifier.setExceptionOnMissingRevocationData(false);
  }

  @Override
  public CertificateSource getTrustedCertSource() {
    return commonCertificateVerifier.getTrustedCertSource();
  }

  @Override
  public void setTrustedCertSource(final CertificateSource trustedCertSource) {
    this.trustedCertSource = trustedCertSource;
    this.commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
  }

  @Override
  public OCSPSource getOcspSource() {
    return this.commonCertificateVerifier.getOcspSource();
  }

  @Override
  public CRLSource getCrlSource() {
    return this.commonCertificateVerifier.getCrlSource();
  }

  @Override
  public void setCrlSource(final CRLSource crlSource) {
    commonCertificateVerifier.setCrlSource(crlSource);
  }

  @Override
  public void setOcspSource(final OCSPSource ocspSource) {
    this.commonCertificateVerifier.setOcspSource(ocspSource);
  }

  @Override
  public CertificateSource getAdjunctCertSource() {
    return this.commonCertificateVerifier.getAdjunctCertSource();
  }

  @Override
  public void setAdjunctCertSource(final CertificateSource adjunctCertSource) {
    this.commonCertificateVerifier.setAdjunctCertSource(adjunctCertSource);
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
  public ListCRLSource getSignatureCRLSource() {
    return this.commonCertificateVerifier.getSignatureCRLSource();
  }

  @Override
  public void setSignatureCRLSource(final ListCRLSource signatureCRLSource) {
    this.commonCertificateVerifier.setSignatureCRLSource(signatureCRLSource);
  }

  @Override
  public ListOCSPSource getSignatureOCSPSource() {
    return this.commonCertificateVerifier.getSignatureOCSPSource();
  }

  @Override
  public void setSignatureOCSPSource(final ListOCSPSource signatureOCSPSource) {
    this.commonCertificateVerifier.setSignatureOCSPSource(signatureOCSPSource);
  }

  @Override
  public CertificatePool createValidationPool() {
    if (this.trustedCertSource == null) {
      return this.commonCertificateVerifier.createValidationPool();
    }
    return new CompoundCertificatePool(this.trustedCertSource);
  }

  @Override
  public void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    commonCertificateVerifier.setDefaultDigestAlgorithm(digestAlgorithm);
  }

  @Override
  public DigestAlgorithm getDefaultDigestAlgorithm() {
    return commonCertificateVerifier.getDefaultDigestAlgorithm();
  }

  @Override
  public void setExceptionOnMissingRevocationData(boolean throwExceptionOnMissingRevocationData) {
    commonCertificateVerifier.setExceptionOnMissingRevocationData(throwExceptionOnMissingRevocationData);
  }

  @Override
  public boolean isExceptionOnMissingRevocationData() {
    return commonCertificateVerifier.isExceptionOnMissingRevocationData();
  }

  @Override
  public boolean isExceptionOnUncoveredPOE() {
    return commonCertificateVerifier.isExceptionOnUncoveredPOE();
  }

  public void setExceptionOnUncoveredPOE(boolean exceptionOnUncoveredPOE) {
    commonCertificateVerifier.setExceptionOnUncoveredPOE(exceptionOnUncoveredPOE);
  }

  @Override
  public boolean isExceptionOnRevokedCertificate() {
    return commonCertificateVerifier.isExceptionOnRevokedCertificate();
  }

  @Override
  public void setExceptionOnRevokedCertificate(boolean exceptionOnRevokedCertificate) {
    commonCertificateVerifier.setExceptionOnRevokedCertificate(exceptionOnRevokedCertificate);
  }

  @Override
  public void setExceptionOnInvalidTimestamp(boolean throwExceptionOnInvalidTimestamp) {
    commonCertificateVerifier.setExceptionOnInvalidTimestamp(throwExceptionOnInvalidTimestamp);
  }

  @Override
  public boolean isExceptionOnInvalidTimestamp() {
    return commonCertificateVerifier.isExceptionOnInvalidTimestamp();
  }

  @Override
  public void setExceptionOnNoRevocationAfterBestSignatureTime(boolean exceptionOnNoRevocationAfterBestSignatureTime) {
    commonCertificateVerifier.setExceptionOnNoRevocationAfterBestSignatureTime(exceptionOnNoRevocationAfterBestSignatureTime);
  }

  @Override
  public boolean isExceptionOnNoRevocationAfterBestSignatureTime() {
    return commonCertificateVerifier.isExceptionOnNoRevocationAfterBestSignatureTime();
  }

  @Override
  public boolean isCheckRevocationForUntrustedChains() {
    return commonCertificateVerifier.isCheckRevocationForUntrustedChains();
  }

  @Override
  public void setCheckRevocationForUntrustedChains(boolean checkRevocationForUntrustedChains) {
    commonCertificateVerifier.setCheckRevocationForUntrustedChains(checkRevocationForUntrustedChains);
  }

  @Override
  public void setIncludeCertificateTokenValues(boolean includeCertificateTokens) {
    commonCertificateVerifier.setIncludeCertificateTokenValues(includeCertificateTokens);
  }

  @Override
  public boolean isIncludeCertificateTokenValues() {
    return commonCertificateVerifier.isIncludeCertificateTokenValues();
  }

  @Override
  public void setIncludeCertificateRevocationValues(boolean include) {
    commonCertificateVerifier.setIncludeCertificateRevocationValues(include);
  }

  @Override
  public boolean isIncludeCertificateRevocationValues() {
    return commonCertificateVerifier.isIncludeCertificateRevocationValues();
  }

  @Override
  public void setIncludeTimestampTokenValues(boolean include) {
    commonCertificateVerifier.setIncludeTimestampTokenValues(include);
  }

  @Override
  public boolean isIncludeTimestampTokenValues() {
    return commonCertificateVerifier.isIncludeTimestampTokenValues();
  }
  
  /*
   * RESTRICTED METHODS
   */

  private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    stream.defaultReadObject();
    this.commonCertificateVerifier = new CommonCertificateVerifier();
  }

}
