package org.digidoc4j;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Signature parameters like production place and roles
 */
public class SignatureParameters implements Serializable {
  private SignatureProductionPlace productionPlace = new SignatureProductionPlace();
  private List<String> roles = new ArrayList<>();
  private String signatureId;

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
}
