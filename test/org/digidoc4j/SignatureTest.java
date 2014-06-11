package org.digidoc4j;

import junit.framework.Assert;

import java.util.Date;

import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;

public class SignatureTest {
  private Signer signer;

  @Before
  public void setUp() {
    signer = new PKCS12Signer("signout.p12", "test");
  }

  @Test
  public void testGetCity() {
    signer.setSignatureProductionPlace("myCity", "myState", "myPostalCode", "myCountry");
    Signature signature = new Signature(null, signer);
    assertEquals("myCity", signature.getCity());
    assertEquals("myCountry", signature.getCountryName());
    assertEquals("myPostalCode", signature.getPostalCode());
    assertEquals("myState", signature.getStateOrProvince());
  }

  @Test
  public void testGetSignerRoles() {
    signer.setSignerRoles(asList("Role / Resolution"));
    Signature signature = new Signature(null, signer);
    Assert.assertEquals(1, signature.getSignerRoles().size());
    assertEquals("Role / Resolution", signature.getSignerRoles().get(0));
  }

  @Test
  public void testGetMultipleSignerRoles() {
    signer.setSignerRoles(asList("Role 1", "Role 2"));
    Signature signature = new Signature(null, signer);
    Assert.assertEquals(2, signature.getSignerRoles().size());
    assertEquals("Role 1", signature.getSignerRoles().get(0));
    assertEquals("Role 2", signature.getSignerRoles().get(1));
  }

  @Test
  @Ignore
  public void testSigningProperties() throws Exception {
    Date dateBeforeTest = new Date();
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    PKCS12Signer signer = new PKCS12Signer("signout.p12", "test");
    signer.setSignatureProductionPlace("city", "stateOrProvince", "postalCode", "country");
    signer.setSignerRoles(asList("signerRoles"));
    Signature signature = bDocContainer.sign(signer);

    //assertTrue(signature.getSigningTime().before(new Date()) && signature.getSigningTime().after(dateBeforeTest));
  }
}
