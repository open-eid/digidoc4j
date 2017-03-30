package org.digidoc4j.exceptions;

import java.io.IOException;

/**
 * Created by Kaarel Raspel on 24/03/17.
 */
public class DigiDoc4JCryptoException extends DigiDoc4JException {
  public DigiDoc4JCryptoException(String message, Exception ex) {
    super(message, ex);
  }

  public DigiDoc4JCryptoException(String message) {
    super(message);
  }
}
