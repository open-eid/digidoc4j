/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import org.digidoc4j.exceptions.DigiDoc4JException;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

/**
 * Signature interface. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public interface Signature extends Serializable {

  /**
   * Sets signer certificate
   * For a BDOC Signature it throws a NotYetImplementedException.
   *
   * @param cert signers certificate
   */
  void setCertificate(X509Cert cert);

  /**
   * Signature validation types.
   */
  enum Validate {
    VALIDATE_TM,
    VALIDATE_POLICY,
    VALIDATE_FULL
  }

  /**
   * Returns the signature production city.
   *
   * @return production city
   */
  String getCity();

  /**
   * Returns the signature production country.
   *
   * @return production country
   */
  String getCountryName();

  /**
   * Returns the signature id.
   *
   * @return id
   */
  String getId();

  /**
   * Returns the signature OCSP response nonce.
   *
   * For a BDOC Signature it throws a NotYetImplementedException.
   *
   * @return OCSP response nonce
   */
  byte[] getOcspNonce();

  /**
   * Returns the signature OCSP responder certificate.
   *
   * @return OCSP responder certificate
   */
  X509Cert getOCSPCertificate();

  /**
   * If the container is DDOC then it returns an empty string.
   *
   * For a BDOC Signature it throws a NotYetImplementedException.
   *
   * @return signature policy
   * @deprecated will be removed in the future
   */
  @Deprecated
  String getPolicy();

  /**
   * Returns the signature production postal code.
   *
   * @return postal code
   */
  String getPostalCode();

  /**
   * Returns the signature OCSP producedAt timestamp.
   *
   * @return producedAt timestamp
   * @deprecated use {@link Signature#getOCSPResponseCreationTime()} instead. Will be removed in the future.
   */
  @Deprecated
  Date getProducedAt();

  Date getOCSPResponseCreationTime();

  /**
   * Returns the signature timestamp generation time.
   *
   * @return generation timestamp
   */
  Date getTimeStampCreationTime();

  /**
   * Returns the signature profile.
   *
   * @return profile
   */
  SignatureProfile getProfile();

  /**
   * Returns the signature method that was used for signing.
   *
   * @return signature method
   */
  String getSignatureMethod();

  /**
   * Returns the signer's roles.
   *
   * @return signer roles
   */
  List<String> getSignerRoles();

  /**
   * Returns the signature certificate that was used for signing.
   *
   * @return signature certificate
   */
  X509Cert getSigningCertificate();

  /**
   * Returns the computer's time of signing.
   *
   * @return signing time
   */
  Date getSigningTime();

  /**
   * If the container is DDoc then it returns an empty string.
   * For a BDOC Signature it throws a NotYetImplementedException.
   *
   * @return signature policy uri
   * @deprecated will be removed in the future
   */
  @Deprecated
  java.net.URI getSignaturePolicyURI();

  /**
   * Returns the signature production state or province.
   *
   * @return production state or province
   */
  String getStateOrProvince();

  /**
   * Returns the signature TimeStampToken certificate.
   * For a DDOC Signature it throws a NotYetImplementedException.
   *
   * @return TimeStampToken certificate
   */
  X509Cert getTimeStampTokenCertificate();

  /**
   * Validates the signature.
   *
   * @param validationType type of validation
   * @return list of Digidoc4JExceptions
   */
  List<DigiDoc4JException> validate(Validate validationType);

  /**
   * Validates the signature using Validate.VALIDATE_FULL method.
   *
   * @return list of Digidoc4JExceptions
   */
  List<DigiDoc4JException> validate();

  /**
   * Returns signature as XAdES XML
   *
   * @return signature as byte array
   */
  byte[] getRawSignature();
}