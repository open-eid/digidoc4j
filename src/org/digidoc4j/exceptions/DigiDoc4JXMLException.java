package org.digidoc4j.exceptions;

/**
 * Created by Kaarel Raspel on 28/03/17.
 */
public class DigiDoc4JXMLException extends DigiDoc4JException {
  public DigiDoc4JXMLException(Exception ex) {
    super(ex);
  }
  public DigiDoc4JXMLException(String message, Exception ex) {
    super(message, ex);
  }
}
