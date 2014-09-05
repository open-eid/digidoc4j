package org.digidoc4j.api;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.BDocContainer;
import org.digidoc4j.Certificates;
import org.digidoc4j.DDocContainer;
import org.digidoc4j.DigiDoc4JTestHelper;
import org.digidoc4j.api.exceptions.CertificateNotFoundException;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.digidoc4j.signers.PKCS12Signer;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import static java.util.Arrays.asList;
import static org.digidoc4j.api.Container.DocumentType.BDOC;
import static org.digidoc4j.api.Container.DocumentType.DDOC;
import static org.digidoc4j.api.Signature.Validate.VALIDATE_FULL;
import static org.digidoc4j.utils.DateUtils.isAlmostNow;
import static org.junit.Assert.*;

public class SignatureTest extends DigiDoc4JTestHelper {

  private PKCS12Signer PKCS12_SIGNER;

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12Signer("testFiles/signout.p12", "test".toCharArray());
  }

  @Test
  public void testSigningProductionPlaceForDDOC() {
    testSigningProductionPlace(Container.create(DDOC));
  }

  @Test
  public void testSigningProductionPlaceForBDoc() {
    testSigningProductionPlace(Container.create(BDOC));
  }

  private void testSigningProductionPlace(Container container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12Signer signer = PKCS12_SIGNER;
    signer.setSignatureProductionPlace("city", "state", "postalCode", "country");
    Signature signature = container.sign(signer);

    assertEquals("country", signature.getCountryName());
    assertEquals("city", signature.getCity());
    assertEquals("state", signature.getStateOrProvince());
    assertEquals("postalCode", signature.getPostalCode());
  }

  @Test
  public void testGetSigningCertificateForBDoc() throws Exception {
    Container container = Container.open("testFiles/asics_for_testing.bdoc");
    byte[] certificate = container.getSignatures().get(0).getSigningCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testGetTimeStampTokenCertificateForBDoc() throws Exception {
    Signature signature = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    byte[] certificate = signature.getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.TS_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetTimeStampTokenCertificateForBDocNoTimeStampExists() throws Exception {
    Container.open("testFiles/asics_for_testing.bdoc").getSignatures().get(0).getTimeStampTokenCertificate();
  }

  @Test(expected = NotYetImplementedException.class)
  public void testSetCertificateForBDOC() throws Exception {
    BDocContainer bDocContainer = new BDocContainer();
    bDocContainer.addDataFile("testFiles/test.txt", "text/plain");
    Signature bDocSignature = bDocContainer.sign(new PKCS12Signer("testFiles/signout.p12", "test".toCharArray()));
    bDocSignature.setCertificate(new X509Cert("testFiles/signout.pem"));
  }

  @Test
  public void testGetSignerRolesForDDOC() {
    testGetSignerRoles(Container.create(DDOC));
  }

  @Test
  public void testGetSignerRolesForBDoc() {
    testGetSignerRoles(Container.create(BDOC));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetSignerRolesForBDoc_OCSP_Exception() {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    List<Signature> signatures = container.getSignatures();
    signatures.get(0).getOCSPCertificate();
  }

  private void testGetSignerRoles(Container container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignerRoles(asList("Role / Resolution"));
    Signature signature = container.sign(PKCS12_SIGNER);
    assertEquals(1, signature.getSignerRoles().size());
    assertEquals("Role / Resolution", signature.getSignerRoles().get(0));
  }

  @Test
  public void testGetRawSignatureForBDoc() {
    Container container = Container.open("testFiles/asics_for_testing.bdoc");
    List<Signature> signatures = container.getSignatures();
    assertEquals("IXMGT0c/U69uEhWZIZvitPQGD29Tx3oKO+9PNijzyRiupcjKTxlH306mbFfIYfVXkiu5n8mA183bzBH/CA5wgbccXwIwykEfay" +
        "Cm2/fGUNm5As9zErnzBWQ4s0oZWIVIi6DFR/QT/rzAoRNJ+1sPZBPvJlPofCW64FgkyADVAUDeCCkV6eAIr2ip+kwduJDmZwxrW/EqU1TA0" +
        "w77lhhAIw4KYEV4yi96eAzDL2rjB8VMUlmLYMnmz1oPdkOGmuj3pbfHV1w4zxYU9uM7LFNN2EogPt4oiH17VSNSlip+HCFdUqvf7hpLFLl2" +
        "iqxgVAijzvw0sMa2p5+iwLUfqCR45w==", new String(signatures.get(0).getRawSignature()));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testGetMultipleSignerRolesForDDOC() {
    testGetMultipleSignerRoles(Container.create(DDOC));
  }

  @Test
  public void testGetMultipleSignerRolesForBDoc() {
    testGetMultipleSignerRoles(Container.create(BDOC));
  }

  private void testGetMultipleSignerRoles(Container container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignerRoles(asList("Role 1", "Role 2"));
    Signature signature = container.sign(PKCS12_SIGNER);
    assertEquals(2, signature.getSignerRoles().size());
    assertEquals("Role 1", signature.getSignerRoles().get(0));
    assertEquals("Role 2", signature.getSignerRoles().get(1));
  }

  @Test
  public void testSigningProperties() throws Exception {
    Container bDocContainer = Container.create(BDOC);
    bDocContainer.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignatureProductionPlace("city", "stateOrProvince", "postalCode", "country");
    PKCS12_SIGNER.setSignerRoles(asList("signerRoles"));
    Signature signature = bDocContainer.sign(PKCS12_SIGNER);

    assertTrue(isAlmostNow(signature.getSigningTime()));
  }

  @Test
  public void testGetSigningTimeForDDOC() {
    testGetSigningTime(DDOC);
  }

  @Test
  public void testGetSigningTimeForBDoc() {
    testGetSigningTime(BDOC);
  }

  private void testGetSigningTime(Container.DocumentType ddoc) {
    Signature signature = getSignature(ddoc);
    assertTrue(isAlmostNow(signature.getSigningTime()));
  }

  @Test
  public void testGetIdForDDOC() {
    Signature signature = getSignature(DDOC);
    assertEquals("S0", signature.getId());
  }

  @Test
  public void testGetIdForBDoc() {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals("id-99E491801522116744419D9357CEFCC5", container.getSignatures().get(0).getId());
  }

  @Test
  public void testGetNonce() {
    Signature signature = getSignature(DDOC);
    assertEquals(null, Base64.encodeBase64String(signature.getNonce())); //todo correct nonce is needed
  }

  @Test
  public void testGetOCSPCertificateForDDoc() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(DDOC));
  }

  @Test
  public void testGetOCSPCertificateForBDoc() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(BDOC));
  }

  private void testGetOCSPCertificate(Signature signature) throws CertificateEncodingException {
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.OCSP_CERTIFICATE, Base64.encodeBase64String(encoded));
  }

  @Test
  public void testGetSignaturePolicyForDDoc() {
    assertEquals("", getSignature(DDOC).getPolicy());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyForBDoc() throws Exception {
    Signature signature = getSignature(BDOC);
    assertEquals("", signature.getPolicy());
  }

  @Test
  public void testGetProducedAtForDDoc() {
    assertTrue(isAlmostNow(getSignature(DDOC).getProducedAt()));
  }

  @Test
  public void testGetProducedAtForBDoc() throws ParseException {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
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
  public void testValidationForBDocDefaultValidation() throws Exception {
    Container container = Container.open("testFiles/two_signatures.bdoc");
    Signature signature = container.getSignatures().get(0);
    assertEquals(0, signature.validate().size());
    signature = container.getSignatures().get(1);
    assertEquals(0, signature.validate().size());
  }

  @Test
  public void testValidationForBDocDefaultValidationWithFailure() throws Exception {
    Signature signature = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    assertEquals(1, signature.validate().size());
  }

  @Test
  public void testValidationForBDocDefaultValidationWithOneFailing() throws Exception {
    Container container = Container.open("testFiles/two_signatures_one_invalid.bdoc");
    Signature signature = container.getSignatures().get(0);
    assertEquals(0, signature.validate().size());
    signature = container.getSignatures().get(1);
    assertEquals(1, signature.validate().size());
  }

  @Test
  public void testValidationWithInvalidDocument() {
    Signature signature = Container.open("testFiles/changed_digidoc_test.ddoc").getSignatures().get(0);
    assertEquals(6, signature.validate(VALIDATE_FULL).size());
  }

  @Test
  public void testGetSignaturePolicyURIForDDoc() {
    assertNull(getSignature(DDOC).getSignaturePolicyURI());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyURIForBDoc() throws Exception {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals(new URI(""), container.getSignatures().get(0).getSignaturePolicyURI());
  }

  @Test
  public void testGetSignatureMethodDDoc() {
    assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", getSignature(DDOC).getSignatureMethod());
  }

  @Test
  public void testGetSignatureMethodForBDoc() {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetProfileForDDoc() {
    assertEquals(Container.SignatureProfile.TM, getSignature(DDOC).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_TS() throws Exception {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals(Container.SignatureProfile.TS, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_None() throws Exception {
    Container container = Container.open("testFiles/asics_for_testing.bdoc");
    assertEquals(Container.SignatureProfile.NONE, container.getSignatures().get(0).getProfile());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetTimeStampTokenCertificateForDDoc() {
    assertNull(getSignature(DDOC).getTimeStampTokenCertificate());
  }

  private Signature getSignature(Container.DocumentType documentType) {
    Container container = Container.create(documentType);
    container.addDataFile("testFiles/test.txt", "text/plain");

    return container.sign(PKCS12_SIGNER);
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetNonceForBDoc() {
    Container container = Container.open("testFiles/asics_for_testing.bdoc");
    container.getSignatures().get(0).getNonce();
  }

  @Test
  public void testGetSignaturesWhereNoSignedDocumentExists() throws Exception {
    DDocContainer container = new DDocContainer("testFiles/no_signed_doc_no_signature.ddoc");
    assertNull(container.getSignatures());
  }

  @Test
  public void testGetSignaturesWhereNoSignaturePresent() throws Exception {
    DDocContainer container = new DDocContainer("testFiles/empty_container_no_signature.ddoc");
    assertNull(container.getSignatures());
  }

  @Test
  public void testGetSignaturesWhereSignatureDoesNotHaveLastCertificate() throws Exception {
    DDocContainer container = new DDocContainer("testFiles/signature_without_last_certificate.ddoc");
    assertEquals(0, container.getSignatures().size());
  }


}

