package org.digidoc4j.exceptions;

public class DataFileMissingException extends DigiDoc4JException {

  public static final String MESSAGE = "No data files specified, but at least 1 is required";

  public DataFileMissingException() {
    super(MESSAGE);
  }

}
