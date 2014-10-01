package org.digidoc4j.impl;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.digidoc4j.impl.ValidationResultForDDoc.isWarning;
import static org.junit.Assert.*;

public class ValidationResultForDDocTest {

  @Test
  public void testIsWarningWhenNoWarningExists() throws DigiDocException {
    assertFalse(isWarning(SignedDoc.FORMAT_DIGIDOC_XML, new DigiDoc4JException(1, "testError")));
  }

  @Test
  public void testIsNotWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsSkXML() throws DigiDocException {
    assertFalse(isWarning(SignedDoc.FORMAT_SK_XML, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsNotSkXML() throws DigiDocException {
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenWarningIsFound() throws DigiDocException {
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH, "test")));
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_OLD_VER, "test")));
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_TEST_SIGNATURE, "test")));
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.WARN_WEAK_DIGEST, "test")));
  }

  @Test
  public void testFromListHasNoErrorsAndNoWarnings() {
    ValidationResultForDDoc result = new ValidationResultForDDoc(null, new ArrayList<DigiDocException>());

    assertFalse(result.hasErrors());
    assertEquals(0, result.getErrors().size());

    assertFalse(result.hasWarnings());
    assertEquals(0, result.getWarnings().size());

    assertTrue(result.isValid());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromListHasErrors() {
    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));

    ValidationResultForDDoc result = new ValidationResultForDDoc(SignedDoc.FORMAT_DIGIDOC_XML, exceptions);
    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();

    assertTrue(result.hasErrors());
    assertEquals(2, errors.size());

    assertFalse(result.hasWarnings());
    assertEquals(0, warnings.size());

    assertFalse(result.isValid());

    assertEquals(DigiDocException.ERR_UNSUPPORTED, errors.get(0).getErrorCode());
    assertEquals(DigiDocException.ERR_UNSUPPORTED + "test; nested exception is: \n\tjava.lang.Throwable: exception1",
        errors.get(0).getMessage());

    assertEquals(DigiDocException.ERR_CALCULATE_DIGEST, errors.get(1).getErrorCode());
    assertEquals(DigiDocException.ERR_CALCULATE_DIGEST + "test2; nested exception is: \n\tjava.lang.Throwable: " +
        "exception2", errors.get(1).getMessage());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromListHasWarnings() {
    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));

    ValidationResultForDDoc result = new ValidationResultForDDoc(SignedDoc.FORMAT_DIGIDOC_XML, exceptions);
    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();

    assertFalse(result.hasErrors());
    assertEquals(0, errors.size());

    assertTrue(result.hasWarnings());
    assertEquals(2, warnings.size());

    assertTrue(result.isValid());

    assertEquals(DigiDocException.ERR_OLD_VER, warnings.get(0).getErrorCode());
    assertEquals(DigiDocException.ERR_OLD_VER + "test; nested exception is: \n\tjava.lang.Throwable: exception1",
        warnings.get(0).getMessage());

    assertEquals(DigiDocException.WARN_WEAK_DIGEST, warnings.get(1).getErrorCode());
    assertEquals(DigiDocException.WARN_WEAK_DIGEST + "test2; nested exception is: \n\tjava.lang.Throwable: " +
        "exception2", warnings.get(1).getMessage());
  }

  @Test
  public void testReport() {
    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));

    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));

    ValidationResultForDDoc result = new ValidationResultForDDoc(SignedDoc.FORMAT_DIGIDOC_XML, exceptions);
    assertEquals("<?xml version=\"1.0\" encoding=\"UTF-16\"?>" +
            "<!--DDoc verification result-->" +
            "<root>" +
            "<error Code=\"15\" Message=\"15test; nested exception is: &#10;&#9;java.lang.Throwable: exception1\"/>" +
            "<error Code=\"54\" Message=\"54test2; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception2\"/><warning " +
            "Code=\"177\" Message=\"177test; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception1\"/><warning " +
            "Code=\"129\" Message=\"129test2; nested exception is: &#10;&#9;java.lang.Throwable: exception2\"/></root>",
        result.getReport());
    System.out.println();
  }

}