package org.digidoc4j;

import org.junit.Test;

import static org.junit.Assert.*;

public class SignatureProductionPlaceTest {

  @Test
  public void setCity() throws Exception {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setCity("City");

    assertEquals("City", signatureProductionPlace.getCity());
  }

  @Test
  public void setStateOrProvince() throws Exception {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setStateOrProvince("StateOrProvince");

    assertEquals("StateOrProvince", signatureProductionPlace.getStateOrProvince());
  }

  @Test
  public void setPostalCode() throws Exception {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setPostalCode("PostalCode");

    assertEquals("PostalCode", signatureProductionPlace.getPostalCode());
  }

  @Test
  public void setCountry() throws Exception {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setCountry("Country");

    assertEquals("Country", signatureProductionPlace.getCountry());
  }
}