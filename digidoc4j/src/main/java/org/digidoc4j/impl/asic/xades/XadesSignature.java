/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.xades;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import org.apache.xml.security.signature.Reference;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.impl.asic.xades.validation.XadesValidationResult;

import eu.europa.esig.dss.xades.validation.XAdESSignature;

/**
 * XadesSignature interface.
 *
 */
public interface XadesSignature extends Serializable {

  /**
   * This method returns signature id(string object).
   *
   * @return signature id.
   */
  String getId();

  /**
   * This method returns the identifier that uniquely identifies this signature.
   *
   * @return unique identifier.
   */
  String getUniqueId();

  /**
   * This method returns city name(string object), it can be empty.
   *
   * @return city.
   */
  String getCity();

  /**
   * This method returns state or province(string object), it can be empty.
   *
   * @return state or province.
   */
  String getStateOrProvince();

  /**
   * This method returns postal code(string object), it can be empty.
   *
   * @return postal code.
   */
  String getPostalCode();

  /**
   * This method returns country name(string object), it can be empty.
   *
   * @return country name.
   */
  String getCountryName();

  /**
   * This method returns signer roles(string list), it can be empty.
   *
   * @return signer roles list.
   */
  List<String> getSignerRoles();

  /**
   * This method returns X509Cert object and it can be null.
   *
   * @return X509Cert
   */
  X509Cert getSigningCertificate();

  /**
   * This method returns signature profile(SignatureProfile object).
   *
   * @return signature profile.
   */
  SignatureProfile getProfile();

  /**
   * This method returns signature method's name(string object), it can be empty.
   *
   * @return signature method's name.
   */
  String getSignatureMethod();

  /**
   * This method returns Date object, it can be null.
   *
   * @return Date
   */
  Date getSigningTime();

  /**
   * Returns signature creation time confirmed by OCSP or TimeStamp authority.
   *
   * Returns OCSP response creation time in case of LT_TM (TimeMark) signatures or
   * Time Stamp creation time in case of LT/LTA (TimeStamp) signatures. Returns null for B_BES signatures.
   *
   * This is much more secure than using signer's computer time that {@link Signature#getClaimedSigningTime()} returns.
   *
   * @return signature creation time confirmed by OCSP or TimeStamp authority.
   */
  Date getTrustedSigningTime();

  /**
   * Returns the signature OCSP producedAt timestamp.
   *
   * @return producedAt timestamp
   * @deprecated use {@link Signature#getOCSPResponseCreationTime()} instead. Will be removed in the future.
   */
  Date getOCSPResponseCreationTime();

  /**
   * Returns the signature OCSP responder certificate.
   *
   * @return OCSP responder certificate
   */
  X509Cert getOCSPCertificate();

  /**
   * Returns the signature OCSP responses list.
   *
   * @return OCSP responses list.
   */
  List<BasicOCSPResp> getOcspResponses();

  /**
   * Returns the signature timestamp generation time.
   *
   * @return generation timestamp
   */
  Date getTimeStampCreationTime();

  /**
   * Returns the signature TimeStampToken certificate.
   * For a DDOC Signature it throws a NotYetImplementedException.
   *
   * @return TimeStampToken certificate
   */
  X509Cert getTimeStampTokenCertificate();

  /**
   * This method returns references list(reference object).
   *
   * @return reference list.
   */
  List<Reference> getReferences();

  /**
   * This method returns signature value(byte object).
   *
   * @return signature value.
   */
  byte[] getSignatureValue();

  /**
   * This method returns XAdES signature(XAdESSignature object).
   *
   * @return XAdESSignature.
   */
  XAdESSignature getDssSignature();

  /**
   * Validates the signature.
   *
   * @return the validation result.
   */
  XadesValidationResult validate();

  /**
   * This method returns the signature OCSP response nonce
   * or {@code null} if OCSP response is not present or OCSP nonce is not found inside the OCSP response.
   *
   * @return OCSP response nonce or {@code null} if not found
   */
  byte[] getOCSPNonce();
}
