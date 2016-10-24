/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class OcspNonceValidator implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(OcspNonceValidator.class);

  private XAdESSignature signature;
  private BasicOCSPResp ocspResponse;

  public OcspNonceValidator(XAdESSignature signature) {
    this.signature = signature;
    ocspResponse = getLatestOcspResponse(signature.getOCSPSource().getContainedOCSPResponses());
  }

  public boolean isValid() {
    if (signature.getPolicyId() == null) {
      return true;
    }
    if (ocspResponse == null) {
      logger.debug("OCSP response was not found in signature: " + signature.getId());
      return true;
    }
    return isOcspResponseValid(ocspResponse);
  }

  private BasicOCSPResp getLatestOcspResponse(List<BasicOCSPResp> ocspResponses) {
    if (ocspResponses.size() == 0) {
      return null;
    }

    BasicOCSPResp basicOCSPResp = ocspResponses.get(0);
    Date latestDate = basicOCSPResp.getProducedAt();

    for (int i = 1; i < ocspResponses.size(); i++) {
      BasicOCSPResp ocspResponse = ocspResponses.get(i);
      if (ocspResponse.getProducedAt().after(latestDate)) {
        latestDate = ocspResponse.getProducedAt();
        basicOCSPResp = ocspResponse;
      }
    }
    return basicOCSPResp;
  }

  private boolean isOcspResponseValid(BasicOCSPResp latestOcspResponse) {
    Extension extension = latestOcspResponse.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"));
    if (extension == null) {
      logger.error("No valid OCSP extension found in signature: " + signature.getId());
      return false;
    }
    return isOcspExtensionValid(extension);
  }

  private boolean isOcspExtensionValid(Extension extension) {
    try {
      byte[] octets = extension.getExtnValue().getOctets();
      byte[] signatureDigestValue = getSignatureDigestValue(octets);
      byte[] foundHash = ((DEROctetString) ASN1Sequence.getInstance(octets).getObjectAt(1)).getOctets();
      boolean extensionHashMatchesSignatureHash = Arrays.equals(foundHash, signatureDigestValue);
      logger.debug("OCSP extension contains valid signature digest: " + extensionHashMatchesSignatureHash);
      return extensionHashMatchesSignatureHash;
    } catch (Exception e) {
      logger.error("Invalid nonce format: " + e.getMessage());
      return false;
    }
  }

  private byte[] getSignatureDigestValue(byte[] octets) {
    DigestAlgorithm usedDigestAlgorithm = getExtensionDigestAlgorithm(octets);
    String signatureValueInBase64 = signature.getSignatureValue().getFirstChild().getNodeValue();
    byte[] signatureValue = Base64.decodeBase64(signatureValueInBase64.getBytes());
    return DSSUtils.digest(usedDigestAlgorithm, signatureValue);
  }

  private DigestAlgorithm getExtensionDigestAlgorithm(byte[] octets) {
    ASN1Encodable oid = ASN1Sequence.getInstance(octets).getObjectAt(0);
    String oidString = ((DLSequence) oid).getObjects().nextElement().toString();
    return DigestAlgorithm.forOID(oidString);
  }
}
