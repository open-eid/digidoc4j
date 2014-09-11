package org.digidoc4j.api;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.junit.Test;

import static org.digidoc4j.api.ValidationResult.isWarning;
import static org.junit.Assert.*;

public class ValidationResultTest {

  @Test
  public void testaddError() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    validationResult.addError(new DigiDoc4JException("testError1"));
    validationResult.addError(new DigiDoc4JException("testError2"));
    assertEquals(2, validationResult.getErrors().size());
  }

  @Test
  public void testGetErrors() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    validationResult.addError(new DigiDoc4JException("testError1"));
    validationResult.addError(new DigiDoc4JException("testError2"));
    assertEquals("testError1", validationResult.getErrors().get(0).getMessage());
    assertEquals("testError2", validationResult.getErrors().get(1).getMessage());
  }

  @Test
  public void testGetErrorsIfNoErrorsExist() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    assertEquals(0, validationResult.getErrors().size());
  }

  @Test
  public void testHasErrors() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    validationResult.addError(new DigiDoc4JException("testError1"));
    assertTrue(validationResult.hasErrors());
  }

  @Test
  public void testHasErrorsIfNoErrorsExist() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    assertFalse(validationResult.hasErrors());
  }

  @Test
  public void testAddWarning() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    validationResult.addWarning(new DigiDoc4JException("testWarning1"));
    validationResult.addWarning(new DigiDoc4JException("testWarning2"));
    assertEquals(2, validationResult.getWarnings().size());
  }

  @Test
  public void testGetWarnings() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    validationResult.addWarning(new DigiDoc4JException("testWarning1"));
    validationResult.addWarning(new DigiDoc4JException("testWarning2"));
    assertEquals("testWarning1", validationResult.getWarnings().get(0).getMessage());
    assertEquals("testWarning2", validationResult.getWarnings().get(1).getMessage());
  }

  @Test
  public void testGetWarningsIfNoWarningsExist() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    assertEquals(0, validationResult.getWarnings().size());
  }

  @Test
  public void testHasWarnings() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    validationResult.addWarning(new DigiDoc4JException("testWarning1"));
    assertTrue(validationResult.hasWarnings());
  }

  @Test
  public void testHasWarningsButNoWarningsExist() throws Exception {
    ValidationResult validationResult = new ValidationResult();
    assertFalse(validationResult.hasWarnings());
  }

  @Test
  public void testIsWarningWhenNoWarningExists() throws DigiDocException {
    MockSignedDoc mockSignedDoc = new MockSignedDoc();
    mockSignedDoc.setFormat(SignedDoc.FORMAT_DIGIDOC_XML);
    assertFalse(isWarning(mockSignedDoc, new DigiDoc4JException(1, "testError")));
  }

  @Test
  public void testIsNotWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsSkXML() throws DigiDocException {
    MockSignedDoc mockSignedDoc = new MockSignedDoc();
    mockSignedDoc.setFormat(SignedDoc.FORMAT_SK_XML);

    assertFalse(isWarning(mockSignedDoc, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS, "testError")));
  }

  @Test
  public void testIsWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsNotSkXML() throws DigiDocException {
    MockSignedDoc mockSignedDoc = new MockSignedDoc();
    mockSignedDoc.setFormat(SignedDoc.FORMAT_DIGIDOC_XML);

    assertTrue(isWarning(mockSignedDoc, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS, "testError")));
  }

  @Test
  public void testIsWarningWhenWarningIsFound() throws DigiDocException {
    MockSignedDoc mockSignedDoc = new MockSignedDoc();
    mockSignedDoc.setFormat(SignedDoc.FORMAT_DIGIDOC_XML);

    assertTrue(isWarning(mockSignedDoc, new DigiDoc4JException(DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH,
        "testError")));
  }

  private class MockSignedDoc extends SignedDoc {
    public MockSignedDoc() {
    }
  }
}