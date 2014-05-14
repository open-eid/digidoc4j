package ee.sk.utils;

import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;

public class PKCS12Signer {
  private DSSPrivateKeyEntry privateKey;

  public PKCS12Signer(final String password, final String pkcs12Keystore) {
    AbstractSignatureTokenConnection token = new Pkcs12SignatureToken(password, pkcs12Keystore);
    privateKey = token.getKeys().get(0);
  }

  public DSSPrivateKeyEntry getPrivateKey() {
    return privateKey;
  }

//  public byte[] getSignature() {
//    byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);
//    byte[] signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
//  }
}
