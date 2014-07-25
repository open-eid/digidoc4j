package org.digidoc4j.main;

import org.digidoc4j.api.exceptions.DigiDoc4JException;

public class DigiDoc4JUtilityException extends DigiDoc4JException {
  private final int errorCode;

  public DigiDoc4JUtilityException(int errorCode, String s) {
    super("DigiDoc4J utility - " + s);
    this.errorCode = errorCode;
  }

  public int getErrorCode() {
    return errorCode;
  }
}
