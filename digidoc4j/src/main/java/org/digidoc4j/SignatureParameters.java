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

import eu.europa.esig.dss.model.Policy;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Signature parameters. Parameter information is used when signing a document. Following items can be specified:
 * <ul>
 *   <li>Signature production place</li>
 *   <li>Roles of the signer</li>
 *   <li>Signature id</li>
 *   <li>Digest algorithm</li>
 *   <li>Encryption algorithm</li>
 *   <li>Signature profile</li>
 *   <li>Signing certificate</li>
 *   <li>Policy</li>
 *   <li>Claimed signing date</li>
 * </ul>
 */
public class SignatureParameters implements Serializable {
  private static final Logger logger = LoggerFactory.getLogger(SignatureParameters.class);
  private SignatureProductionPlace productionPlace = new SignatureProductionPlace();
  private List<String> roles = new ArrayList<>();
  private String signatureId;
  private DigestAlgorithm digestAlgorithm;
  private EncryptionAlgorithm encryptionAlgorithm;
  private SignatureProfile signatureProfile;
  private X509Certificate signingCertificate;
  private Policy policy;
  private Date claimedSigningDate;

  /**
   * Get production place values.
   *
   * @return production place
   * @deprecated
   */
  public SignatureProductionPlace getProductionPlace() {
    return productionPlace;
  }

  public String getCity() {
    return productionPlace.getCity();
  }

  public void setCity(String city) {
    productionPlace.setCity(city);
  }

  public String getStateOrProvince() {
    return productionPlace.getStateOrProvince();
  }

  public void setStateOrProvince(String stateOrProvince) {
    productionPlace.setStateOrProvince(stateOrProvince);
  }

  public String getPostalCode() {
    return productionPlace.getPostalCode();
  }

  public void setPostalCode(String postalCode) {
    productionPlace.setPostalCode(postalCode);
  }

  public String getCountry() {
    return productionPlace.getCountry();
  }

  public void setCountry(String country) {
    productionPlace.setCountry(country);
  }

  /**
   * Get signing roles.
   *
   * @return signing roles
   */
  public List<String> getRoles() {
    return roles;
  }

  /**
   * Set the production place.
   *
   * @param productionPlace production place
   * @deprecated
   */
  public void setProductionPlace(SignatureProductionPlace productionPlace) {
    this.productionPlace = productionPlace;
  }

  /**
   * Set signing roles.
   *
   * @param roles signing roles
   */
  public void setRoles(List<String> roles) {
    this.roles = roles;
  }

  /**
   * Set signature id.
   *
   * @param signatureId signature ID
   */
  public void setSignatureId(String signatureId) {
    logger.debug("Set signature id to " + signatureId);
    this.signatureId = signatureId;
  }

  /**
   * Get signature id.
   *
   * @return signature ID
   */
  public String getSignatureId() {
    return signatureId;
  }

  /**
   * Sets container digest type
   *
   * @param algorithm digest algorithm
   */
  public void setDigestAlgorithm(DigestAlgorithm algorithm) {
    digestAlgorithm = algorithm;
  }

  /**
   * Gets container digest type
   *
   * @return container digest algorithm
   */
  public DigestAlgorithm getDigestAlgorithm() {
    return digestAlgorithm;
  }

  /**
   * Get the encryption algorithm
   *
   * @return encryption algorithm
   */
  public EncryptionAlgorithm getEncryptionAlgorithm() {
    return encryptionAlgorithm;
  }

  /**
   * Set the encryption algorithm
   *
   * @param encryptionAlgorithm encryption algorithm to use
   */
  public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
    this.encryptionAlgorithm = encryptionAlgorithm;
  }

  public SignatureProfile getSignatureProfile() {
    return signatureProfile;
  }

  public void setSignatureProfile(SignatureProfile signatureProfile) {
    this.signatureProfile = signatureProfile;
  }

  public void setSigningCertificate(X509Certificate signingCertificate) {
    this.signingCertificate = signingCertificate;
  }

  public X509Certificate getSigningCertificate() {
    return signingCertificate;
  }

  public Policy getPolicy() {
    return policy;
  }

  public void setPolicy(Policy policy) {
    this.policy = policy;
  }

  public Date getClaimedSigningDate() {
    return claimedSigningDate;
  }

  public void setClaimedSigningDate(Date claimedSigningDate) {
    this.claimedSigningDate = claimedSigningDate;
  }

  /**
   * Clones signature parameters
   *
   * @return new signature parameters object
   */
  public SignatureParameters copy() {
    ObjectOutputStream oos = null;
    ObjectInputStream ois = null;
    SignatureParameters copySignatureParameters = null;
    // deep copy
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try {
      oos = new ObjectOutputStream(bos);
      oos.writeObject(this);
      oos.flush();
      ByteArrayInputStream bin =
          new ByteArrayInputStream(bos.toByteArray());
      ois = new ObjectInputStream(bin);
      copySignatureParameters = (SignatureParameters) ois.readObject();
    } catch (Exception e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(oos);
      IOUtils.closeQuietly(ois);
      IOUtils.closeQuietly(bos);
    }
    return copySignatureParameters;
  }
}
