/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.TechnicalException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class CertificateUtils {

  public static boolean isEcdsaCertificate(X509Certificate certificate) {
    if (certificate == null) {
      return false;
    }

    String algorithm = certificate.getPublicKey().getAlgorithm();
    return algorithm.equals("EC") || algorithm.equals("ECC");
  }

  public static X509Cert toX509Cert(X509CertificateHolder certificateHolder) {
    return new X509Cert(toX509Certificate(certificateHolder));
  }

  public static X509Certificate toX509Certificate(X509CertificateHolder certificateHolder) {
    try {
      return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    } catch (CertificateException e) {
        throw new TechnicalException("Failed to convert certificate", e);
    }
  }

  private CertificateUtils() {
  }

}
