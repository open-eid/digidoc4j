package org.digidoc4j.main;

import org.digidoc4j.api.exceptions.DigiDoc4JException;

public class DigiDoc4JUtilityException extends DigiDoc4JException {
  private final int errorCode;

  public DigiDoc4JUtilityException(int errorCode, DigiDoc4JException exception) {
    super("DigiDoc4J utility - " + exception.getClass().getName() + " : " + exception.getMessage() + "\n");
    this.errorCode = errorCode;
  }

  public DigiDoc4JUtilityException(int errorCode, String message) {
    super("DigiDoc4J utility - " + message + "\n");
    this.errorCode = errorCode;
  }

  public int getErrorCode() {
    return errorCode;
  }
}
