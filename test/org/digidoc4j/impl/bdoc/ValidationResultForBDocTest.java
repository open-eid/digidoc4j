/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;


import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Test;
import org.w3c.dom.Element;

import javax.imageio.metadata.IIOMetadataNode;
import java.util.*;

import static java.util.Arrays.asList;
import static junit.framework.TestCase.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import eu.europa.esig.dss.asic.validation.ASiCXMLDocumentValidator;
import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;

public class ValidationResultForBDocTest {


  @Test
  public void testFromValidatorHasNoErrorsAndNoWarnings() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIdList()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());
    when(simpleReport.getWarnings("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());

    Reports report = mock(Reports.class);
    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.validateDocument()).thenReturn(report);
    when(report.getSimpleReport()).thenReturn(simpleReport);

    Element rootElement = mock(Element.class);
    when(rootElement.getChildNodes()).thenReturn(new IIOMetadataNode());
    when(simpleReport.getRootElement()).thenReturn(rootElement);

    /*
    ValidationResultForBDoc result = new ValidationResultForBDoc(report, new ArrayList<Signature>(),
        new ArrayList<String>(), new HashMap<String, List<DigiDoc4JException>>());

    assertFalse(result.hasErrors());
    assertFalse(result.hasWarnings());
    */
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromValidatorHasErrors() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIdList()).thenReturn(asList("S0"));
    when(simpleReport.getWarnings("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());

    Reports report = mock(Reports.class);
    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.validateDocument()).thenReturn(report);
    when(report.getSimpleReport()).thenReturn(simpleReport);

    Element rootElement = mock(Element.class);
    when(rootElement.getChildNodes()).thenReturn(new IIOMetadataNode());
    when(simpleReport.getRootElement()).thenReturn(rootElement);

    Signature signature = mock(Signature.class);
    when(signature.validate()).thenReturn(asList(new DigiDoc4JException("Error1"), new DigiDoc4JException("Error2")));

    /*
    ValidationResult result = new ValidationResultForBDoc(report, asList(signature), new ArrayList<String>(),
        new HashMap<String, List<DigiDoc4JException>>());

    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();

    assertTrue(result.hasErrors());

    assertEquals(2, errors.size());
    assertEquals("Error1", errors.get(0).getMessage());
    assertEquals("Error2", errors.get(1).getMessage());

    assertEquals(0, warnings.size());
    assertFalse(result.hasWarnings());

    assertFalse(result.isValid());
    */
  }


  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromValidatorHasWarnings() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    when(simpleReport.getSignatureIdList()).thenReturn(asList("S0"));
    when(simpleReport.getErrors("S0")).thenReturn(new ArrayList<Conclusion.BasicInfo>());
    when(simpleReport.getWarnings("S0")).thenReturn(
        asList(new Conclusion.BasicInfo("Warning", "Warning1"), new Conclusion.BasicInfo("Warning", "Warning2")));

    Reports report = mock(Reports.class);
    ASiCXMLDocumentValidator validator = mock(ASiCXMLDocumentValidator.class);
    when(validator.validateDocument()).thenReturn(report);
    when(report.getSimpleReport()).thenReturn(simpleReport);

    Element rootElement = mock(Element.class);
    when(rootElement.getChildNodes()).thenReturn(new IIOMetadataNode());
    when(simpleReport.getRootElement()).thenReturn(rootElement);
    /*
    ValidationResult result = new ValidationResultForBDoc(report, new ArrayList<Signature>(),
        new ArrayList<String>(), new HashMap<String, List<DigiDoc4JException>>());

    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();

    assertFalse(result.hasErrors());
    assertEquals(0, errors.size());

    assertTrue(result.hasWarnings());
    assertEquals(2, warnings.size());


    assertEquals("Warning1", warnings.get(0).getMessage());
    assertEquals("Warning2", warnings.get(1).getMessage());

    assertTrue(result.isValid());
    */
  }
}
