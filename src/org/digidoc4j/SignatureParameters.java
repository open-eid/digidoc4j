package org.digidoc4j;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Signature parameters like production place and roles
 */
public class SignatureParameters implements Serializable {
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
    return productionPlace;
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
    this.signatureId = signatureId;
  }

  /**
   * Get signature id.
   *
   * @return signatureId signature ID
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
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(oos);
      IOUtils.closeQuietly(ois);
      IOUtils.closeQuietly(bos);
    }
    return copySignatureParameters;
  }
}
