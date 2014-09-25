package org.digidoc4j.api.exceptions;

public class UnsupportedFormatException extends DigiDoc4JException {
  public UnsupportedFormatException(String type) {
    super(type);
  }
}
