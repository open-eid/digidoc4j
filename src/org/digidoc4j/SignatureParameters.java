package org.digidoc4j;

import java.util.ArrayList;
import java.util.List;

public class SignatureParameters {
  private SignatureProductionPlace productionPlace = new SignatureProductionPlace();
  private List<String> roles = new ArrayList<>();

  public SignatureProductionPlace getProductionPlace() {
    return productionPlace;
  }

  public List<String> getRoles() {
    return roles;
  }

  public void setProductionPlace(SignatureProductionPlace productionPlace) {
    this.productionPlace = productionPlace;
  }

  public void setRoles(List<String> roles) {
    this.roles = roles;
  }
}
