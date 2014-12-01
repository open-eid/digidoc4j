/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;

import eu.europa.ec.markt.dss.validation102853.*;
import eu.europa.ec.markt.dss.validation102853.crl.CRLSource;
import eu.europa.ec.markt.dss.validation102853.crl.ListCRLSource;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.ocsp.ListOCSPSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPSource;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Delegate class for SD-DSS CommonCertificateVerifier. Needed for making serialization possible
 */
public class SKCommonCertificateVerifier
    implements Serializable, CertificateVerifier {

  private transient CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

  private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    stream.defaultReadObject();
    commonCertificateVerifier = new CommonCertificateVerifier();
  }

  @Override
  public TrustedCertificateSource getTrustedCertSource() {
    return commonCertificateVerifier.getTrustedCertSource();
  }

  @Override
  public OCSPSource getOcspSource() {
    return commonCertificateVerifier.getOcspSource();
  }

  @Override
  public CRLSource getCrlSource() {
    return commonCertificateVerifier.getCrlSource();
  }

  @Override
  public void setCrlSource(final CRLSource crlSource) {
    commonCertificateVerifier.setCrlSource(crlSource);
  }

  @Override
  public void setOcspSource(final OCSPSource ocspSource) {
    commonCertificateVerifier.setOcspSource(ocspSource);
  }

  @Override
  public void setTrustedCertSource(final TrustedCertificateSource trustedCertSource) {
    commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
  }

  @Override
  public CertificateSource getAdjunctCertSource() {
    return commonCertificateVerifier.getAdjunctCertSource();
  }

  @Override
  public void setAdjunctCertSource(final CertificateSource adjunctCertSource) {
    commonCertificateVerifier.setAdjunctCertSource(adjunctCertSource);
  }

  @Override
  public DataLoader getDataLoader() {
    return commonCertificateVerifier.getDataLoader();
  }

  @Override
  public void setDataLoader(final DataLoader dataLoader) {
    commonCertificateVerifier.setDataLoader(dataLoader);
  }

  @Override
  public ListCRLSource getSignatureCRLSource() {
    return commonCertificateVerifier.getSignatureCRLSource();
  }

  @Override
  public void setSignatureCRLSource(final ListCRLSource signatureCRLSource) {
    commonCertificateVerifier.setSignatureCRLSource(signatureCRLSource);
  }

  @Override
  public ListOCSPSource getSignatureOCSPSource() {
    return commonCertificateVerifier.getSignatureOCSPSource();
  }

  @Override
  public void setSignatureOCSPSource(final ListOCSPSource signatureOCSPSource) {
    commonCertificateVerifier.setSignatureOCSPSource(signatureOCSPSource);
  }

  @Override
  public CertificatePool createValidationPool() {
    return commonCertificateVerifier.createValidationPool();
  }
}
