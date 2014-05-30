package prototype;

import ee.sk.digidoc4j.X509Cert;

import java.util.List;

/**
 * Implements the Signer interface for ID-Cards, which support PKCS#11 protocol
 * <p>
 * The method selectSigningCertificate is called if the signer needs to choose the correct signing certificate.
 * It is also called if there is only one certificate found on ID-Card.
 * Parameter certificates provides a list of all certificates found in the ID-Card.
 * </p><p>
 * The method pin is called if the selected certificate requires a PIN in order to log in.
 * </p>
 */
public class PKCS11Signer {

  /**
   * Loads PKCS#11 driver
   *
   * @param driver full path to the PKCS#11 driver (e.g. /usr/lib/opensc-pkcs11.so)
   * @throws Exception thrown if the provided PKCS#11 driver loading failed
   */
  PKCS11Signer(String driver) throws Exception {
  }

  /**
   * Returns the PIN code for the selected signing certificate
   * If no PIN code is required then this method is never called
   * To cancel the login this method should throw an exception
   *
   * @param certificate certificate that is used for signing and needs a PIN for login
   * @return the PIN code to login
   * @throws Exception should throw an exception if the login operation should be canceled
   */
  protected String getPin(X509Cert certificate) throws Exception {
    return null;
  }

  /**
   * Abstract method for selecting the correct signing certificate.
   * If none of the certificates are suitable for signing, this method should throw an Exception.
   * This method is always called, when there is at least 1 certificate available
   *
   * @param certificates available certificates to choose from
   * @return the certificate used for signing
   * @throws Exception if no suitable certificate is in the list or the operation should be cancelled
   */
  protected X509Cert selectSigningCertificate(List<X509Cert> certificates) throws Exception {
    return null;
  }

  /**
   * If sub class does not want to reimplement the pin method then it is possible to set a default pin
   *
   * @param pin pin code to set as default pin
   */
  public void setPin(String pin) {
  }
}






