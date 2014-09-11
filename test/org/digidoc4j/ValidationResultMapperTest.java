package org.digidoc4j;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import org.digidoc4j.api.ValidationResult;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.digidoc4j.ValidationResultMapper.isWarning;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ValidationResultMapperTest {

  @Test
  public void testIsWarningWhenNoWarningExists() throws DigiDocException {
    SignedDoc signedDoc = new SignedDoc();
    assertFalse(isWarning(signedDoc.getFormat(), new DigiDoc4JException(1, "testError")));
  }

  @Test
  public void testIsNotWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsSkXML() throws DigiDocException {
    SignedDoc signedDoc = new SignedDoc();
    signedDoc.setFormat(SignedDoc.FORMAT_SK_XML);

    assertFalse(isWarning(signedDoc.getFormat(), new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsNotSkXML() throws DigiDocException {
    SignedDoc signedDoc = new SignedDoc();
    signedDoc.setFormat(SignedDoc.FORMAT_DIGIDOC_XML);

    assertTrue(isWarning(signedDoc.getFormat(), new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenWarningIsFound() throws DigiDocException {
    SignedDoc signedDoc = new SignedDoc();
    String format = signedDoc.getFormat();
    assertTrue(isWarning(format, new DigiDoc4JException(DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH, "test")));
    assertTrue(isWarning(format, new DigiDoc4JException(DigiDocException.ERR_OLD_VER, "test")));
    assertTrue(isWarning(format, new DigiDoc4JException(DigiDocException.ERR_TEST_SIGNATURE, "test")));
    assertTrue(isWarning(format, new DigiDoc4JException(DigiDocException.WARN_WEAK_DIGEST, "test")));
  }


  @Test
  public void testFromValidatorHasNoErrorsAndNoWarnings() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIds()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());
    when(simpleReport.getWarnings("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());

    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.getSimpleReport()).thenReturn(simpleReport);

    ValidationResult result = ValidationResultMapper.fromValidator(validator);

    assertFalse(result.hasErrors());
    assertFalse(result.hasWarnings());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromValidatorHasErrors() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIds()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(asList(new Conclusion.BasicInfo("Error", "Error1"),
        new Conclusion.BasicInfo("Error", "Error2")));
    when(simpleReport.getWarnings("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());

    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.getSimpleReport()).thenReturn(simpleReport);

    ValidationResult result = ValidationResultMapper.fromValidator(validator);

    assertTrue(result.hasErrors());
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals("Error1", errors.get(0).getMessage());
    assertEquals("Error2", errors.get(1).getMessage());

    assertFalse(result.hasWarnings());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromValidatorHasWarnings() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIds()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());
    when(simpleReport.getWarnings("S0")).thenReturn(
        asList(new Conclusion.BasicInfo("Warning", "Warning1"), new Conclusion.BasicInfo("Warning", "Warning2")));

    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.getSimpleReport()).thenReturn(simpleReport);

    ValidationResult result = ValidationResultMapper.fromValidator(validator);

    assertFalse(result.hasErrors());

    assertTrue(result.hasWarnings());
    List<DigiDoc4JException> warnings = result.getWarnings();
    assertEquals("Warning1", warnings.get(0).getMessage());
    assertEquals("Warning2", warnings.get(1).getMessage());
  }


  @Test
  public void testFromListHasNoErrorsAndNoWarnings() {
    SignedDoc signedDoc = new SignedDoc();

    ValidationResult validationResult = ValidationResultMapper.fromList(signedDoc.getFormat(),
        new ArrayList<DigiDocException>());
    assertFalse(validationResult.hasWarnings());
    assertFalse(validationResult.hasErrors());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromListHasErrors() {
    SignedDoc signedDoc = new SignedDoc();

    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));

    ValidationResult validationResult = ValidationResultMapper.fromList(signedDoc.getFormat(), exceptions);
    List<DigiDoc4JException> errors = validationResult.getErrors();

    assertTrue(validationResult.hasErrors());

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
    SignedDoc signedDoc = new SignedDoc();

    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));

    ValidationResult validationResult = ValidationResultMapper.fromList(signedDoc.getFormat(), exceptions);
    List<DigiDoc4JException> warnings = validationResult.getWarnings();

    assertTrue(validationResult.hasWarnings());

    assertEquals(DigiDocException.ERR_OLD_VER, warnings.get(0).getErrorCode());
    assertEquals(DigiDocException.ERR_OLD_VER + "test; nested exception is: \n\tjava.lang.Throwable: exception1",
        warnings.get(0).getMessage());

    assertEquals(DigiDocException.WARN_WEAK_DIGEST, warnings.get(1).getErrorCode());
    assertEquals(DigiDocException.WARN_WEAK_DIGEST + "test2; nested exception is: \n\tjava.lang.Throwable: " +
        "exception2", warnings.get(1).getMessage());
  }
}