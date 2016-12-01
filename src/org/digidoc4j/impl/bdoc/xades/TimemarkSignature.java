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

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.x509.CertificateToken;

public class TimemarkSignature extends BesSignature {

  private final static Logger logger = LoggerFactory.getLogger(TimemarkSignature.class);
  private X509Cert ocspCertificate;
  private transient BasicOCSPResp ocspResponse;
  private Date ocspResponseTime;

  public TimemarkSignature(XadesValidationReportGenerator xadesReportGenerator) {
    super(xadesReportGenerator);
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
    ocspCertificate = findOcspCertificate();
    return ocspCertificate;
  }

  @Override
  public List<BasicOCSPResp> getOcspResponses() {
    return getDssSignature().getOCSPSource().getContainedOCSPResponses();
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
    List<BasicOCSPResp> containedOCSPResponses = getOcspResponses();
    if (containedOCSPResponses.isEmpty()) {
      logger.debug("Contained OCSP responses is empty");
      return null;
    }
    if (containedOCSPResponses.size() > 1) {
      logger.warn("Signature contains more than one OCSP response: " + containedOCSPResponses.size() + ". Using the first one.");
    }
    return containedOCSPResponses.get(0);
  }

  private X509Cert findOcspCertificate() {
    String ocspCN = getOCSPCommonName();
    for (CertificateToken cert : getDssSignature().getCertificates()) {
      String certCn = getCN(new X500Name(cert.getSubjectX500Principal().getName()));
      if (StringUtils.equals(certCn, ocspCN)) {
        return new X509Cert(cert.getCertificate());
      }
    }
    logger.error("OCSP certificate for " + ocspCN + " was not found in TSL");
    throw new CertificateNotFoundException("OCSP certificate for " + ocspCN + " was not found in TSL");
  }

  private String getOCSPCommonName() {
    RespID responderId = ocspResponse.getResponderId();
    String commonName = getCN(responderId.toASN1Primitive().getName());
    logger.debug("OCSP common name: " + commonName);
    return commonName;
  }

  private String getCN(X500Name x500Name) {
    RDN[] rdNs = x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.3"));
    if (rdNs == null || rdNs.length == 0) {
      return null;
    }
    AttributeTypeAndValue[] typesAndValues = rdNs[0].getTypesAndValues();
    if (typesAndValues == null || typesAndValues.length == 0) {
      return null;
    }
    String name = typesAndValues[0].getValue().toString();
    return name;
  }
}
