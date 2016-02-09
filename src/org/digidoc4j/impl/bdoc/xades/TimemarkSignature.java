/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades;

import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class TimemarkSignature extends BesSignature {

  private final static Logger logger = LoggerFactory.getLogger(TimemarkSignature.class);
  private XAdESSignature dssSignature;
  private X509Cert ocspCertificate;
  private BasicOCSPResp ocspResponse;
  private Date ocspResponseTime;

  public TimemarkSignature(XAdESSignature dssSignature) {
    super(dssSignature);
    this.dssSignature = dssSignature;
  }

  @Override
  public SignatureProfile getProfile() {
    return SignatureProfile.LT_TM;
  }

  @Override
  public X509Cert getOCSPCertificate() {
    if (ocspCertificate != null) {
      return ocspCertificate;
    }
    initOcspResponse();
    if (ocspResponse == null) {
      return null;
    }
    ocspCertificate = findOcspCertificate(ocspResponse);
    return ocspCertificate;
  }

  @Override
  public Date getOCSPResponseCreationTime() {
    if (ocspResponseTime != null) {
      return ocspResponseTime;
    }
    initOcspResponse();
    if (ocspResponse == null) {
      return null;
    }
    ocspResponseTime = ocspResponse.getProducedAt();
    return ocspResponseTime;
  }

  @Override
  public Date getTrustedSigningTime() {
    return getOCSPResponseCreationTime();
  }

  private void initOcspResponse() {
    if (ocspResponse == null) {
      ocspResponse = findOcspResponse();
      if (ocspResponse == null) {
        logger.warn("Signature is missing OCSP response");
      }
    }
  }

  private BasicOCSPResp findOcspResponse() {
    logger.debug("Finding OCSP response");
    List<BasicOCSPResp> containedOCSPResponses = dssSignature.getOCSPSource().getContainedOCSPResponses();
    if (containedOCSPResponses.isEmpty()) {
      logger.debug("Contained OCSP responses is empty");
      return null;
    }
    if (containedOCSPResponses.size() > 1) {
      logger.warn("Signature contains more than one OCSP response: " + containedOCSPResponses.size() + ". Using the first one.");
    }
    return containedOCSPResponses.get(0);
  }

  private X509Cert findOcspCertificate(BasicOCSPResp ocspResponse) {
    String ocspCN = getOCSPCommonName(ocspResponse);
    Set<CertificateToken> certificates = getEncapsulatedCertificates();
    for (CertificateToken cert : certificates) {
      String certCn = getCN(new X500Name(cert.getSubjectX500Principal().getName()));
      if (certCn.equals(ocspCN)) {
        X509Cert x509Cert = new X509Cert(cert.getCertificate());
        return x509Cert;
      }
    }
    logger.warn("Signature is missing OCSP response");
    return null;
  }

  private String getOCSPCommonName(BasicOCSPResp ocspResponse) {
    RespID responderId = ocspResponse.getResponderId();
    String commonName = getCN(responderId.toASN1Object().getName());
    logger.debug("OCSP common name: " + commonName);
    return commonName;
  }

  private String getCN(X500Name x500Name) {
    String name = x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.3"))[0].getTypesAndValues()[0].getValue().toString();
    return name;
  }
}
