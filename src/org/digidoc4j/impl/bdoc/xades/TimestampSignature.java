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
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class TimestampSignature extends TimemarkSignature {

  private final static Logger logger = LoggerFactory.getLogger(TimestampSignature.class);
  private Element signatureElement;
  private XPathQueryHolder xPathQueryHolder;
  private TimeStampToken timeStampToken;
  private X509Cert timestampTokenCertificate;

  public TimestampSignature(XAdESSignature dssSignature) {
    super(dssSignature);
    this.xPathQueryHolder = getxPathQueryHolder();
    this.signatureElement = getSignatureElement();
  }

  @Override
  public SignatureProfile getProfile() {
    return SignatureProfile.LT;
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    if (timestampTokenCertificate != null) {
      return timestampTokenCertificate;
    }
    if (timeStampToken == null) {
      timeStampToken = findTimestampToken();
    }
    if (timeStampToken == null) {
      logger.warn("Timestamp token was not found");
    }
    timestampTokenCertificate = findTimestampTokenCertificate(timeStampToken);
    return timestampTokenCertificate;
  }

  @Override
  public Date getTimeStampCreationTime() {
    if (timeStampToken == null) {
      timeStampToken = findTimestampToken();
    }
    if (timeStampToken == null || timeStampToken.getTimeStampInfo() == null) {
      logger.warn("Timestamp token was not found");
      return null;
    }
    return timeStampToken.getTimeStampInfo().getGenTime();
  }

  @Override
  public Date getTrustedSigningTime() {
    return getTimeStampCreationTime();
  }

  private TimeStampToken findTimestampToken() {
    logger.debug("Finding timestamp token");
    NodeList timestampNodes = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_TIMESTAMP);
    if (timestampNodes.getLength() == 0) {
      logger.warn("Signature timestamp element was not found");
      return null;
    }
    if (timestampNodes.getLength() > 1) {
      logger.warn("Signature contains more than one timestamp: " + timestampNodes.getLength() + ". Using only the first one");
    }
    Node timestampNode = timestampNodes.item(0);
    Element timestampTokenNode = DSSXMLUtils.getElement(timestampNode, xPathQueryHolder.XPATH__ENCAPSULATED_TIMESTAMP);
    if (timestampTokenNode == null) {
      logger.warn("The timestamp cannot be extracted from the signature");
      return null;
    }
    String base64EncodedTimestamp = timestampTokenNode.getTextContent();
    return createTimeStampToken(base64EncodedTimestamp);
  }

  private TimeStampToken createTimeStampToken(final String base64EncodedTimestamp) throws DSSException {
    logger.debug("Creating timestamp token");
    try {
      byte[] tokenBytes = Base64.decodeBase64(base64EncodedTimestamp);
      CMSSignedData signedData = new CMSSignedData(tokenBytes);
      return new TimeStampToken(signedData);
    } catch (Exception e) {
      logger.error("Error parsing timestamp token: " + e.getMessage());
      throw new TechnicalException("Error parsing timestamp token", e);
    }
  }

  private X509Cert findTimestampTokenCertificate(TimeStampToken timeStamp) {
    logger.debug("Finding timestamp token certificate");
    Set<CertificateToken> certs = getEncapsulatedCertificates();
    for (CertificateToken certificateToken : certs) {
      X509CertificateHolder x509CertificateHolder = createX509CertificateHolder(certificateToken);
      if (timeStamp.getSID().match(x509CertificateHolder)) {
        return new X509Cert(certificateToken.getCertificate());
      }
    }
    logger.warn("Timestamp token certificate was not found");
    return null;
  }

  private X509CertificateHolder createX509CertificateHolder(CertificateToken certificateToken) {
    byte[] encoded = certificateToken.getEncoded();
    Certificate certificate = Certificate.getInstance(encoded);
    return new X509CertificateHolder(certificate);
  }
}
