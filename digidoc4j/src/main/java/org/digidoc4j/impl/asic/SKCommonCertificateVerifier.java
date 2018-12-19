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

import org.digidoc4j.impl.asic.tsl.ClonedTslCertificateSource;
import org.digidoc4j.impl.asic.tsl.LazyCertificatePool;
import org.digidoc4j.impl.asic.tsl.LazyTslCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.ListCRLSource;
import eu.europa.esig.dss.x509.ocsp.ListOCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * Delegate class for SD-DSS CommonCertificateVerifier. Needed for making serialization possible
 */
public class SKCommonCertificateVerifier implements Serializable, CertificateVerifier {

  private final Logger log = LoggerFactory.getLogger(SKCommonCertificateVerifier.class);
  private transient CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
  private transient CertificateSource trustedCertSource;

  @Override
  public CertificateSource getTrustedCertSource() {
    if (this.trustedCertSource instanceof ClonedTslCertificateSource) {
      if (((ClonedTslCertificateSource) this.trustedCertSource).getTrustedListsCertificateSource() != null) {
        this.log.debug("get TrustedListCertificateSource from ClonedTslCertificateSource");
        return ((ClonedTslCertificateSource) this.trustedCertSource).getTrustedListsCertificateSource();
      }
    }
    return this.commonCertificateVerifier.getTrustedCertSource();
  }

  @Override
  public void setTrustedCertSource(final CertificateSource trustedCertSource) {
    ClonedTslCertificateSource clonedTslCertificateSource = new ClonedTslCertificateSource(trustedCertSource);
    this.trustedCertSource = clonedTslCertificateSource;
    if (trustedCertSource instanceof LazyTslCertificateSource) {
      this.log.debug("get TrustedCertSource from LazyTslCertificateSource");
      this.commonCertificateVerifier.setTrustedCertSource(
          ((LazyTslCertificateSource) trustedCertSource).getTslLoader().getTslCertificateSource());
    } else {
      this.commonCertificateVerifier.setTrustedCertSource(clonedTslCertificateSource);
    }
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
    return new LazyCertificatePool(this.trustedCertSource);
  }
  
  /*
   * RESTRICTED METHODS
   */

  private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    stream.defaultReadObject();
    this.commonCertificateVerifier = new CommonCertificateVerifier();
  }

}
