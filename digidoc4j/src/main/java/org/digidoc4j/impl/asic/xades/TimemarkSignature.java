/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Signature for BDOC where timemark is taken from OCSP response.
 */
public class TimemarkSignature extends BesSignature {

  private static final Logger logger = LoggerFactory.getLogger(TimemarkSignature.class);
  private transient X509Cert ocspCertificate;
  private transient BasicOCSPResp ocspResponse;
  private transient Date ocspResponseTime;
  private transient byte[] ocspNonce;

  /**
   * @param xadesReportGenerator XADES validation report generator
   */
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
    return getDssSignature().getOCSPSource().getAllRevocationBinaries()
            .stream()
            .map(rb -> {
              try {
                return DSSRevocationUtils.loadOCSPFromBinaries(rb.getBinaries());
              } catch (IOException e) {
                throw new IllegalArgumentException("Invalid ocsp binary");
              }
            })
            .collect(Collectors.toList());
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

  @Override
  public byte[] getOCSPNonce() {
    if (ocspNonce != null) {
      return ocspNonce;
    }
    initOcspResponse();
    if (ocspResponse == null) {
      return null;
    }
    Extension nonceExt = ocspResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    if (nonceExt == null) {
      return null;
    }
    ocspNonce = nonceExt.getExtnValue().getOctets();
    return ocspNonce;
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
      logger.warn("Signature contains more than one OCSP response: "
              + containedOCSPResponses.size() + ". Using the first one.");
    }
    return containedOCSPResponses.get(0);
  }

  private X509Cert findOcspCertificate() {
    String rId = "";
    String signatureId = getDssSignature().getId();
    try {
      RespID responderId = ocspResponse.getResponderId();
      rId = responderId.toString();
      String primitiveName = getCN(responderId.toASN1Primitive().getName());
      byte[] keyHash = responderId.toASN1Primitive().getKeyHash();

      boolean isKeyHash = useKeyHashForOCSP(primitiveName, keyHash);

      if (isKeyHash) {
        logger.debug("Using keyHash {} for OCSP certificate match", keyHash);
      } else {
        logger.debug("Using ASN1Primitive {} for OCSP certificate match", primitiveName);
      }

      for (CertificateToken cert : getDssSignature().getCertificates()) {
        if (isKeyHash) {
          ASN1Primitive skiPrimitive = JcaX509ExtensionUtils.parseExtensionValue(
                  cert.getCertificate().getExtensionValue(Extension.subjectKeyIdentifier.getId()));
          byte[] keyIdentifier = ASN1OctetString.getInstance(skiPrimitive.getEncoded()).getOctets();
          if (Arrays.equals(keyHash, keyIdentifier)) {
            return new X509Cert(cert.getCertificate());
          }
        } else {

          String certCn = getCN(new X500Name(cert.getSubject().getPrincipal().getName()));
          if (StringUtils.equals(certCn, primitiveName)) {
            return new X509Cert(cert.getCertificate());
          }
        }
      }

    } catch (IOException e) {
      logger.error("Unable to wrap and extract SubjectKeyIdentifier from certificate - technical error. {}", e);
    }

    logger.error("OCSP certificate for " + rId + " was not found in TSL");
    throw new CertificateNotFoundException("OCSP certificate for " + rId + " was not found in TSL", signatureId);
  }

  private boolean useKeyHashForOCSP(String primitiveName, byte[] keyHash) {
    return (keyHash != null && keyHash.length > 0) && (primitiveName == null || primitiveName.trim().length() == 0);
  }


  private String getCN(X500Name x500Name) {
    if (x500Name == null) return null;
    RDN[] rdNs = x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.3"));
    if (rdNs == null || rdNs.length == 0) {
      return null;
    }
    AttributeTypeAndValue[] typesAndValues = rdNs[0].getTypesAndValues();
    if (typesAndValues == null || typesAndValues.length == 0) {
      return null;
    }
    return typesAndValues[0].getValue().toString();
  }
}
