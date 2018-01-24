package org.digidoc4j.impl.asic.ocsp;


import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.xades.signature.DSSSignatureUtils;

/**
 * BDocTMOcspSource is class for creating BDoc TM specific NONCE.
 */
public class BDocTMOcspSource extends SKOnlineOCSPSource {
  private static final Logger logger = LoggerFactory.getLogger(SKOnlineOCSPSource.class);
  private final byte[] signature;

  /**
   * Constructor.
   * @param configuration Configuration.
   * @param signature Signature value without DER prefixes.
   */
  public BDocTMOcspSource(Configuration configuration, byte[] signature) {
    super(configuration);
    this.signature = signature;
    logger.debug("Using TM OCSP source");
  }

  @Override
  Extension createNonce() {
    try {
      boolean critical = false;
      return new Extension(id_pkix_ocsp_nonce, critical, createNonceAsn1Sequence().getEncoded());
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private DERSequence createNonceAsn1Sequence() {
    ASN1Object nonceComponents[] = new ASN1Object[2];
    nonceComponents[0] = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256");
    nonceComponents[1] = new DEROctetString(DSSUtils.digest(DigestAlgorithm.SHA256, signature));
    return new DERSequence(nonceComponents);
  }
}
