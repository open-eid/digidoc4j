package org.digidoc4j.utils;

import java.security.cert.X509Certificate;

public final class CertificateUtils {

  public static boolean isEcdsaCertificate(X509Certificate certificate) {
    if (certificate == null) {
      return false;
    }

    String algorithm = certificate.getPublicKey().getAlgorithm();
    return algorithm.equals("EC") || algorithm.equals("ECC");
  }
}
