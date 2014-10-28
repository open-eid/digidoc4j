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

public class SKCommonCertificateVerifier
    implements Serializable, CertificateVerifier {

  private transient CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

  private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    stream.defaultReadObject();
    commonCertificateVerifier = new CommonCertificateVerifier();
  }

  public TrustedCertificateSource getTrustedCertSource() {
    return commonCertificateVerifier.getTrustedCertSource();
  }

  public OCSPSource getOcspSource() {
    return commonCertificateVerifier.getOcspSource();
  }

  public CRLSource getCrlSource() {
    return commonCertificateVerifier.getCrlSource();
  }

  public void setCrlSource(final CRLSource crlSource) {
    commonCertificateVerifier.setCrlSource(crlSource);
  }

  public void setOcspSource(final OCSPSource ocspSource) {
    commonCertificateVerifier.setOcspSource(ocspSource);
  }

  public void setTrustedCertSource(final TrustedCertificateSource trustedCertSource) {
    commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
  }

  public CertificateSource getAdjunctCertSource() {
    return commonCertificateVerifier.getAdjunctCertSource();
  }

  public void setAdjunctCertSource(final CertificateSource adjunctCertSource) {
    commonCertificateVerifier.setAdjunctCertSource(adjunctCertSource);
  }

  public DataLoader getDataLoader() {
    return commonCertificateVerifier.getDataLoader();
  }

  public void setDataLoader(final DataLoader dataLoader) {
    commonCertificateVerifier.setDataLoader(dataLoader);
  }

  public ListCRLSource getSignatureCRLSource() {
    return commonCertificateVerifier.getSignatureCRLSource();
  }

  public void setSignatureCRLSource(final ListCRLSource signatureCRLSource) {
    commonCertificateVerifier.setSignatureCRLSource(signatureCRLSource);
  }

  public ListOCSPSource getSignatureOCSPSource() {
    return commonCertificateVerifier.getSignatureOCSPSource();
  }

  public void setSignatureOCSPSource(final ListOCSPSource signatureOCSPSource) {
    commonCertificateVerifier.setSignatureOCSPSource(signatureOCSPSource);
  }

  public CertificatePool createValidationPool() {
    return commonCertificateVerifier.createValidationPool();
  }
}
