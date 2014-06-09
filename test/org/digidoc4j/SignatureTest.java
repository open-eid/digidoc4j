package org.digidoc4j;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import junit.framework.Assert;

import java.util.Date;

import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static java.util.Arrays.asList;
import static junit.framework.Assert.assertNull;
import static org.junit.Assert.assertEquals;

public class SignatureTest {
  private SignatureParameters signatureParameters;
  private SignerLocation signerLocation = new SignerLocation();

  @Before
  public void setUp() throws Exception {
    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_LT);
    signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
  }

  @Test
  public void testGetCity() {
    signerLocation.setCity("myCity");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertEquals("myCity", signature.getCity());
  }

  @Test
  public void testGetCityWhereNull() {
    signerLocation.setCity(null);
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertNull(signature.getCity());
  }

  @Test
  public void testGetCityWhereEmpty() {
    signerLocation.setCity("");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertEquals("", signature.getCity());
  }

  @Test
  public void testCountryName() {
    signerLocation.setCountry("myCountry");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertEquals("myCountry", signature.getCountryName());
  }

  @Test
  public void testGetCountryNameWhereNull() {
    signerLocation.setCountry(null);
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertNull(signature.getCountryName());
  }

  @Test
  public void testGetCountryNameWhereEmpty() {
    signerLocation.setCountry("");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertEquals("", signature.getCountryName());
  }

  @Test
  public void testPostalCode() {
    signerLocation.setPostalCode("myPostalCode");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertEquals("myPostalCode", signature.getPostalCode());
  }

  @Test
  public void testGetPostalCodeWhereNull() {
    signerLocation.setPostalCode(null);
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertNull(signature.getPostalCode());
  }

  @Test
  public void testGetPostalCodeWhereEmpty() {
    signerLocation.setPostalCode("");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertEquals("", signature.getPostalCode());
  }

  @Test
  public void testStateOrProvince() {
    signerLocation.setStateOrProvince("myState");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertEquals("myState", signature.getStateOrProvince());
  }

  @Test
  public void testGetStateOrProvinceWhereNull() {
    signerLocation.setStateOrProvince(null);
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertNull(signature.getStateOrProvince());
  }

  @Test
  public void testGetStateOrProvinceWhereEmpty() {
    signerLocation.setStateOrProvince("");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    assertEquals("", signature.getStateOrProvince());
  }

  @Test
  public void testGetSignerRoles() {
    signatureParameters.bLevel().addClaimedSignerRole("Role / Resolution");
    signatureParameters.bLevel().setSignerLocation(signerLocation);
    Signature signature = new Signature(null, signatureParameters);
    Assert.assertEquals(1, signature.getSignerRoles().size());
    assertEquals("Role / Resolution", signature.getSignerRoles().get(0));
  }

  @Test
  public void testGetMultipleSignerRoles() {
    signatureParameters.bLevel().addClaimedSignerRole("Role 1");
    signatureParameters.bLevel().addClaimedSignerRole("Role 2");
    Signature signature = new Signature(null, signatureParameters);
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
