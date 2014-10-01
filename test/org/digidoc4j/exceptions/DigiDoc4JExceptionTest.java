package org.digidoc4j.exceptions;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DigiDoc4JExceptionTest {

  @Test
  public void toStringWithNoErrorCode() throws Exception {
    DigiDoc4JException error = new DigiDoc4JException("Error");
    assertEquals("Error", error.toString());
  }

  @Test
  public void toStringWithErrorCode() throws Exception {
    DigiDoc4JException error = new DigiDoc4JException(5, "Error");
    assertEquals("ERROR: 5 - Error", error.toString());
  }


}