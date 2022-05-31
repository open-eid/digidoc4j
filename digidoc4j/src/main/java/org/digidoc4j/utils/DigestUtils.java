package org.digidoc4j.utils;

import org.digidoc4j.DigestAlgorithm;

import java.security.interfaces.ECPublicKey;

public final class DigestUtils {

  public static DigestAlgorithm getRecommendedSignatureDigestAlgorithm(ECPublicKey ecPublicKey) {
    int keySizeInBits = ecPublicKey.getParams().getOrder().bitLength();
    if (keySizeInBits == 256) {
      return DigestAlgorithm.SHA256;
    } else if (keySizeInBits == 384) {
      return DigestAlgorithm.SHA384;
    } else {
      return DigestAlgorithm.SHA512;
    }
  }

}
