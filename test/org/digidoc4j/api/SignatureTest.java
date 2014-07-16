package org.digidoc4j.api;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.Certificates;
import org.digidoc4j.ContainerImpl;
import org.digidoc4j.DigiDoc4JTestHelper;
import org.digidoc4j.SignatureImpl;
import org.digidoc4j.api.exceptions.CertificateNotFoundException;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import static java.util.Arrays.asList;
import static org.digidoc4j.api.Container.DocumentType.ASIC_S;
import static org.digidoc4j.api.Container.DocumentType.DDOC;
import static org.digidoc4j.api.Signature.Validate.VALIDATE_FULL;
import static org.digidoc4j.utils.DateUtils.isAlmostNow;
import static org.junit.Assert.*;

public class SignatureTest extends DigiDoc4JTestHelper {

  private PKCS12Signer PKCS12_SIGNER;

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12Signer("testFiles/signout.p12", "test");
  }

  @Test
  public void testSigningProductionPlaceForDDOC() {
    testSigningProductionPlace(new ContainerImpl(DDOC));
  }

  @Test
  public void testSigningProductionPlaceForASiCS() {
    testSigningProductionPlace(new ContainerImpl(ASIC_S));
  }

  private void testSigningProductionPlace(ContainerImpl container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12Signer signer = PKCS12_SIGNER;
    signer.setSignatureProductionPlace("city", "state", "postalCode", "country");
    SignatureImpl signature = container.sign(signer);

    assertEquals("country", signature.getCountryName());
    assertEquals("city", signature.getCity());
    assertEquals("state", signature.getStateOrProvince());
    assertEquals("postalCode", signature.getPostalCode());
  }

  @Test
  public void testGetSigningCertificateForASiCS() throws Exception {
    ContainerImpl container = new ContainerImpl("testFiles/asics_for_testing.asics");
    byte[] certificate = container.getSignatures().get(0).getSigningCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testGetTimeStampTokenCertificateForASiCS() throws Exception {
    SignatureImpl signature = new ContainerImpl("testFiles/ocsp_cert_is_not_in_tsl.asics").getSignatures().get(0);
    byte[] certificate = signature.getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.TS_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetTimeStampTokenCertificateForASiCSNoTimeStampExists() throws Exception {
    new ContainerImpl("testFiles/asics_for_testing.asics").getSignatures().get(0).getTimeStampTokenCertificate();
  }

  @Test
  public void testGetSignerRolesForDDOC() {
    testGetSignerRoles(new ContainerImpl(DDOC));
  }

  @Test
  public void testGetSignerRolesForASiCS() {
    testGetSignerRoles(new ContainerImpl(ASIC_S));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetSignerRolesForASiCS_OCSP_Exception() {
    ContainerImpl container = new ContainerImpl("testFiles/ocsp_cert_is_not_in_tsl.asics");
    List<SignatureImpl> signatures = container.getSignatures();
    signatures.get(0).getOCSPCertificate();
  }

  private void testGetSignerRoles(ContainerImpl container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignerRoles(asList("Role / Resolution"));
    SignatureImpl signature = container.sign(PKCS12_SIGNER);
    assertEquals(1, signature.getSignerRoles().size());
    assertEquals("Role / Resolution", signature.getSignerRoles().get(0));
  }

  @Test
  public void testGetRawSignatureForASiCS() {
    ContainerImpl container = new ContainerImpl("testFiles/asics_for_testing.asics");
    List<SignatureImpl> signatures = container.getSignatures();
    assertEquals("IXMGT0c/U69uEhWZIZvitPQGD29Tx3oKO+9PNijzyRiupcjKTxlH306mbFfIYfVXkiu5n8mA183bzBH/CA5wgbccXwIwykEfay" +
                 "Cm2/fGUNm5As9zErnzBWQ4s0oZWIVIi6DFR/QT/rzAoRNJ+1sPZBPvJlPofCW64FgkyADVAUDeCCkV6eAIr2ip+kwduJDmZwxrW/EqU1TA0" +
                 "w77lhhAIw4KYEV4yi96eAzDL2rjB8VMUlmLYMnmz1oPdkOGmuj3pbfHV1w4zxYU9uM7LFNN2EogPt4oiH17VSNSlip+HCFdUqvf7hpLFLl2" +
                 "iqxgVAijzvw0sMa2p5+iwLUfqCR45w==", new String(signatures.get(0).getRawSignature()));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testGetMultipleSignerRolesForDDOC() {
    testGetMultipleSignerRoles(new ContainerImpl(DDOC));
  }

  @Test
  public void testGetMultipleSignerRolesForASiCS() {
    testGetMultipleSignerRoles(new ContainerImpl(ASIC_S));
  }

  private void testGetMultipleSignerRoles(ContainerImpl container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignerRoles(asList("Role 1", "Role 2"));
    SignatureImpl signature = container.sign(PKCS12_SIGNER);
    assertEquals(2, signature.getSignerRoles().size());
    assertEquals("Role 1", signature.getSignerRoles().get(0));
    assertEquals("Role 2", signature.getSignerRoles().get(1));
  }

  @Test
  public void testSigningProperties() throws Exception {
    ContainerImpl bDocContainer = new ContainerImpl();
    bDocContainer.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignatureProductionPlace("city", "stateOrProvince", "postalCode", "country");
    PKCS12_SIGNER.setSignerRoles(asList("signerRoles"));
    SignatureImpl signature = bDocContainer.sign(PKCS12_SIGNER);

    assertTrue(isAlmostNow(signature.getSigningTime()));
  }

  @Test
  public void testGetSigningTimeForDDOC() {
    testGetSigningTime(DDOC);
  }

  @Test
  public void testGetSigningTimeForASiCS() {
    testGetSigningTime(ASIC_S);
  }

  private void testGetSigningTime(Container.DocumentType ddoc) {
    SignatureImpl signature = getSignature(ddoc);
    assertTrue(isAlmostNow(signature.getSigningTime()));
  }

  @Test
  public void testGetIdForDDOC() {
    SignatureImpl signature = getSignature(DDOC);
    assertEquals("S0", signature.getId());
  }

  @Test
  public void testGetIdForASiCS() {
    ContainerImpl container = new ContainerImpl("testFiles/ocsp_cert_is_not_in_tsl.asics");
    assertEquals("id-99E491801522116744419D9357CEFCC5", container.getSignatures().get(0).getId());
  }

  @Test
  public void testGetNonce() {
    SignatureImpl signature = getSignature(DDOC);
    assertEquals(null, Base64.encodeBase64String(signature.getNonce())); //todo correct nonce is needed
  }

  @Test
  public void testGetOCSPCertificateForDDoc() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(DDOC));
  }

  @Test
  public void testGetOCSPCertificateForASiCS() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(ASIC_S));
  }

  private void testGetOCSPCertificate(SignatureImpl signature) throws CertificateEncodingException {
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.OCSP_CERTIFICATE, Base64.encodeBase64String(encoded));
  }

  @Test
  public void testGetSignaturePolicyForDDoc() {
    assertEquals("", getSignature(DDOC).getPolicy());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyForASiCS() throws Exception {
    SignatureImpl signature = getSignature(ASIC_S);
    assertEquals("", signature.getPolicy());
  }

  @Test
  public void testGetProducedAtForDDoc() {
    assertTrue(isAlmostNow(getSignature(DDOC).getProducedAt()));
  }

  @Test
  public void testGetProducedAtForASiCS() throws ParseException {
    ContainerImpl container = new ContainerImpl("testFiles/ocsp_cert_is_not_in_tsl.asics");
    Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z").parse("2014-07-08 12:51:16 +0000");
    assertEquals(date, container.getSignatures().get(0).getProducedAt());
  }

  @Test
  public void testValidationForDDoc() {
    assertEquals(0, getSignature(DDOC).validate(VALIDATE_FULL).size());
  }

  @Test
  public void testValidationNoParametersForDDoc() {
    assertEquals(0, getSignature(DDOC).validate().size());
  }

  @Test
  public void testValidationForASiCSDefaultValidation() throws Exception {
    ContainerImpl container = new ContainerImpl("testFiles/two_signatures.asics");
    SignatureImpl signature = container.getSignatures().get(0);
    assertEquals(0, signature.validate().size());
    signature = container.getSignatures().get(1);
    assertEquals(0, signature.validate().size());
  }

  @Test
  public void testValidationForASiCSDefaultValidationWithFailure() throws Exception {
    SignatureImpl signature = new ContainerImpl("testFiles/ocsp_cert_is_not_in_tsl.asics").getSignatures().get(0);
    assertEquals(1, signature.validate().size());
  }

  @Test
  public void testValidationForASiCSDefaultValidationWithOneFailing() throws Exception {
    ContainerImpl container = new ContainerImpl("testFiles/two_signatures_one_invalid.asics");
    SignatureImpl signature = container.getSignatures().get(0);
    assertEquals(0, signature.validate().size());
    signature = container.getSignatures().get(1);
    assertEquals(1, signature.validate().size());
  }

  @Test
  public void testValidationWithInvalidDocument() {
    SignatureImpl signature = new ContainerImpl("testFiles/changed_digidoc_test.ddoc").getSignatures().get(0);
    assertEquals(6, signature.validate(VALIDATE_FULL).size());
  }

  @Test
  public void testGetSignaturePolicyURIForDDoc() {
    assertNull(getSignature(DDOC).getSignaturePolicyURI());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyURIForASiCS() throws Exception {
    ContainerImpl container = new ContainerImpl("testFiles/ocsp_cert_is_not_in_tsl.asics");
    assertEquals(new URI(""), container.getSignatures().get(0).getSignaturePolicyURI());
  }

  @Test
  public void testGetSignatureMethodDDoc() {
    assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", getSignature(DDOC).getSignatureMethod());
  }

  @Test
  public void testGetSignatureMethodForASiCS() {
    ContainerImpl container = new ContainerImpl("testFiles/ocsp_cert_is_not_in_tsl.asics");
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256",
                 container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetProfileForDDoc() {
    assertEquals(Container.SignatureProfile.TM, getSignature(DDOC).getProfile());
  }

  @Test
  public void testGetProfileForASiCS_TS() throws Exception {
    ContainerImpl container = new ContainerImpl("testFiles/ocsp_cert_is_not_in_tsl.asics");
    assertEquals(Container.SignatureProfile.TS, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForASiCS_None() throws Exception {
    ContainerImpl container = new ContainerImpl("testFiles/asics_for_testing.asics");
    assertEquals(Container.SignatureProfile.NONE, container.getSignatures().get(0).getProfile());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetTimeStampTokenCertificateForDDoc() {
    assertNull(getSignature(DDOC).getTimeStampTokenCertificate());
  }

  private SignatureImpl getSignature(Container.DocumentType documentType) {
    ContainerImpl container = new ContainerImpl(documentType);
    container.addDataFile("testFiles/test.txt", "text/plain");

    return container.sign(PKCS12_SIGNER);
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetNonceForASiCS() {
    ContainerImpl container = new ContainerImpl("testFiles/asics_for_testing.asics");
    container.getSignatures().get(0).getNonce();
  }
}
