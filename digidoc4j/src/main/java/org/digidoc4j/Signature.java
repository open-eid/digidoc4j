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

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Signature interface. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public interface Signature extends Serializable {

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
   * Returns the identifier that uniquely identifies this signature.
   *
   * @return unique identifier
   */
  String getUniqueId();

  /**
   * Returns the signature OCSP response nonce
   * or {@code null} if OCSP response is not present or OCSP nonce is not found inside the OCSP response.
   *
   * @return OCSP response nonce or {@code null} if not found
   */
  byte[] getOCSPNonce();

  /**
   * Returns the signature OCSP responder certificate.
   *
   * @return OCSP responder certificate
   */
  X509Cert getOCSPCertificate();

  /**
   * If the container is DDOC then it returns an empty string.
   * <p>
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

  /**
   * Returns the signature OCSP producedAt timestamp.
   *
   * @return producedAt timestamp
   */
  Date getOCSPResponseCreationTime();

  /**
   * Returns the signature timestamp generation time.
   *
   * @return generation timestamp
   */
  Date getTimeStampCreationTime();

  /**
   * Returns signature creation time confirmed by OCSP or TimeStamp authority.
   * <p>
   * Returns OCSP response creation time in case of LT_TM (TimeMark) signatures or
   * Time Stamp creation time in case of LT/LTA (TimeStamp) signatures. Returns null for B_BES signatures.
   * <p>
   * This is much more secure than using signer's computer time that {@link Signature#getClaimedSigningTime()} returns.
   *
   * @return signature creation time confirmed by OCSP or TimeStamp authority.
   */
  Date getTrustedSigningTime();

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
   * <p>
   * See also {@link Signature#getTrustedSigningTime()}
   *
   * @return signing time
   */
  Date getClaimedSigningTime();

  /**
   * Returns the computer's time of signing.
   *
   * @return signing time
   * @deprecated use {@link Signature#getClaimedSigningTime()} instead. Will be removed in the future.
   */
  @Deprecated
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
   * @return the validation result.
   */
  ValidationResult validateSignature();

  /**
   * Validates the signature.
   *
   * @return list of Digidoc4JExceptions
   * @deprecated use {@link Signature#validateSignature()} instead.
   */
  @Deprecated
  List<DigiDoc4JException> validate();

  /**
   * Returns signature as XAdES XML
   *
   * @return signature as byte array
   */
  byte[] getAdESSignature();

  /**
   * @return signature as byte array
   * @deprecated use {@link Signature#getAdESSignature()} instead.
   */
  @Deprecated
  byte[] getRawSignature();
}
