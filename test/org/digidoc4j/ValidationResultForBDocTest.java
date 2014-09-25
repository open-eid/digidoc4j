package org.digidoc4j;

import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import org.digidoc4j.api.ValidationResult;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static junit.framework.TestCase.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ValidationResultForBDocTest {

  @Test
  public void testFromValidatorHasNoErrorsAndNoWarnings() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIds()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());
    when(simpleReport.getWarnings("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());

    Reports report = mock(Reports.class);
    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.validateDocument()).thenReturn(report);
    when(report.getSimpleReport()).thenReturn(simpleReport);

    ValidationResultForBDoc result = new ValidationResultForBDoc(report);

    assertFalse(result.hasErrors());
    assertFalse(result.hasWarnings());
  }

  @Test
  public void testGetReport() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    String reportContent = "test report";

    when(simpleReport.toString()).thenReturn(reportContent);
    when(simpleReport.getSignatureIds()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());
    when(simpleReport.getWarnings("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());

    Reports report = mock(Reports.class);
    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.validateDocument()).thenReturn(report);
    when(report.getSimpleReport()).thenReturn(simpleReport);

    ValidationResultForBDoc result = new ValidationResultForBDoc(report);

    assertEquals(reportContent, result.getReport());
  }



  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromValidatorHasErrors() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIds()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(asList(new Conclusion.BasicInfo("Error", "Error1"),
        new Conclusion.BasicInfo("Error", "Error2")));
    when(simpleReport.getWarnings("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());

    Reports report = mock(Reports.class);
    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.validateDocument()).thenReturn(report);
    when(report.getSimpleReport()).thenReturn(simpleReport);

    ValidationResult result = new ValidationResultForBDoc(report);

    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();

    assertTrue(result.hasErrors());

    assertEquals(2, errors.size());
    assertEquals("Error1", errors.get(0).getMessage());
    assertEquals("Error2", errors.get(1).getMessage());

    assertEquals(0, warnings.size());
    assertFalse(result.hasWarnings());

    assertFalse(result.isValid());
  }


  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromValidatorHasWarnings() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIds()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());
    when(simpleReport.getWarnings("S0")).thenReturn(
        asList(new Conclusion.BasicInfo("Warning", "Warning1"), new Conclusion.BasicInfo("Warning", "Warning2")));

    Reports report = mock(Reports.class);
    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.validateDocument()).thenReturn(report);
    when(report.getSimpleReport()).thenReturn(simpleReport);

    ValidationResult result = new ValidationResultForBDoc(report);

    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();

    assertFalse(result.hasErrors());
    assertEquals(0, errors.size());

    assertTrue(result.hasWarnings());
    assertEquals(2, warnings.size());


    assertEquals("Warning1", warnings.get(0).getMessage());
    assertEquals("Warning2", warnings.get(1).getMessage());

    assertTrue(result.isValid());
  }
}