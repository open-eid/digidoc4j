package org.digidoc4j.api;

import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.junit.Assert.*;

public class ValidationResultTest {

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testGetErrors() throws Exception {
    List<DigiDoc4JException> errors =
        asList(new DigiDoc4JException("testError1"), new DigiDoc4JException("testError2"));
    List<DigiDoc4JException> warnings = new ArrayList<DigiDoc4JException>();

    ValidationResult validationResult = new ValidationResult(errors, warnings);

    assertEquals("testError1", validationResult.getErrors().get(0).getMessage());
    assertEquals("testError2", validationResult.getErrors().get(1).getMessage());
  }

  @Test
  public void testGetErrorsIfNoErrorsExist() throws Exception {
    ValidationResult validationResult =
        new ValidationResult(new ArrayList<DigiDoc4JException>(), new ArrayList<DigiDoc4JException>());

    assertEquals(0, validationResult.getErrors().size());
  }

  @Test
  public void testHasErrorsIfErrorsExist() throws Exception {
    ValidationResult validationResult =
        new ValidationResult(asList(new DigiDoc4JException("testError1")), new ArrayList<DigiDoc4JException>());

    assertTrue(validationResult.hasErrors());
  }

  @Test
  public void testHasErrorsIfNoErrorsExist() throws Exception {
    ValidationResult validationResult =
        new ValidationResult(new ArrayList<DigiDoc4JException>(), new ArrayList<DigiDoc4JException>());

    assertFalse(validationResult.hasErrors());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testGetWarnings() throws Exception {
    List<DigiDoc4JException> errors = new ArrayList<DigiDoc4JException>();
    List<DigiDoc4JException> warnings =
        asList(new DigiDoc4JException("testWarning1"), new DigiDoc4JException("testWarning2"));

    ValidationResult validationResult = new ValidationResult(errors, warnings);

    assertEquals("testWarning1", validationResult.getWarnings().get(0).getMessage());
    assertEquals("testWarning2", validationResult.getWarnings().get(1).getMessage());
  }

  @Test
  public void testGetWarningsIfNoWarningsExist() throws Exception {
    ValidationResult validationResult =
        new ValidationResult(new ArrayList<DigiDoc4JException>(), new ArrayList<DigiDoc4JException>());

    assertEquals(0, validationResult.getWarnings().size());
  }

  @Test
  public void testHasWarningsIfWarningsExist() throws Exception {
    ValidationResult validationResult =
        new ValidationResult(new ArrayList<DigiDoc4JException>(), asList(new DigiDoc4JException("testWarning1")));

    assertTrue(validationResult.hasWarnings());
  }

  @Test
  public void testHasWarningsIfNoWarningsExist() throws Exception {
    ValidationResult validationResult =
        new ValidationResult(new ArrayList<DigiDoc4JException>(), new ArrayList<DigiDoc4JException>());
    assertFalse(validationResult.hasWarnings());
  }


}
