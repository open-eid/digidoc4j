package org.digidoc4j.exceptions;

public class TimestampAfterOCSPResponseTimeException extends DigiDoc4JException {

  public static final String MESSAGE = "Timestamp time is after OCSP response production time";

  public TimestampAfterOCSPResponseTimeException() {
    super(MESSAGE);
  }

}
