package org.digidoc4j.testutils;

import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;

public class TestHelpers {

  public static boolean containsErrorMessage(List<DigiDoc4JException> errors, String message) {
    List<String> errorMessages = new ArrayList<>();
    for (DigiDoc4JException error : errors) {
      errorMessages.add(error.getMessage());
    }
    return errorMessages.contains(message);
  }
}
