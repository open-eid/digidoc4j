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

import org.apache.commons.io.IOUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Signature parameters. Parameter information is used when signing a document. Following items can be specified:
 * <ul>
 *   <li>Signature production place</li>
 *   <li>Roles of the signer</li>
 *   <li>Signature id</li>
 *   <li>Digest algorithm</li>
 * </ul>
 */
public class SignatureParameters implements Serializable {
  final Logger logger = LoggerFactory.getLogger(SignatureParameters.class);
  private SignatureProductionPlace productionPlace = new SignatureProductionPlace();
  private List<String> roles = new ArrayList<>();
  private String signatureId;
  private DigestAlgorithm digestAlgorithm;

  /**
   * Get production place values.
   *
   * @return production place
   */
  public SignatureProductionPlace getProductionPlace() {
    logger.debug("Production place: " + productionPlace);
    return productionPlace;
  }

  /**
   * Get signing roles.
   *
   * @return signing roles
   */
  public List<String> getRoles() {
    logger.debug("");
    return roles;
  }

  /**
   * Set the production place.
   *
   * @param productionPlace production place
   */
  public void setProductionPlace(SignatureProductionPlace productionPlace) {
    logger.debug("Set production place to " + productionPlace);
    this.productionPlace = productionPlace;
  }

  /**
   * Set signing roles.
   *
   * @param roles signing roles
   */
  public void setRoles(List<String> roles) {
    logger.debug("");
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
   * @return signatureId signature ID
   */
  public String getSignatureId() {
    logger.debug("Get signature id returns " + signatureId);
    return signatureId;
  }

  /**
   * Sets container digest type
   *
   * @param algorithm digest algorithm
   */
  public void setDigestAlgorithm(DigestAlgorithm algorithm) {
    logger.debug("");
    digestAlgorithm = algorithm;
  }

  /**
   * Gets container digest type
   *
   * @return container digest algorithm
   */
  public DigestAlgorithm getDigestAlgorithm() {
    logger.debug("");
    return digestAlgorithm;
  }

  /**
   * Clones signature parameters
   *
   * @return new signature parameters object
   */
  public SignatureParameters copy() {
    logger.debug("");
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
