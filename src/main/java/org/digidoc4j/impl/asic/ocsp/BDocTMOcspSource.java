package org.digidoc4j.impl.asic.ocsp;


import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * BDocTMOcspSource is class for creating BDoc TM specific NONCE.
 */
public class BDocTMOcspSource extends SKOnlineOCSPSource {

  private static final Logger logger = LoggerFactory.getLogger(BDocTMOcspSource.class);
  private final byte[] signature;

  /**
   * @param configuration Configuration.
   * @param signature     Signature value without DER prefixes.
   */
  public BDocTMOcspSource(Configuration configuration, byte[] signature) {
    super(configuration);
    this.signature = signature;
  }

  @Override
  protected Extension createNonce() {
    logger.debug("Creating TM OCSP nonce ...");
    try {
      return new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, this.createSequence().getEncoded());
    } catch (IOException e) {
      throw new DigiDoc4JException(e);
    }
  }

  private DERSequence createSequence() {
    ASN1Object nonceComponents[] = new ASN1Object[2];
    nonceComponents[0] = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256");
    nonceComponents[1] = new DEROctetString(DSSUtils.digest(DigestAlgorithm.SHA256, this.signature));
    return new DERSequence(nonceComponents);
  }

}
