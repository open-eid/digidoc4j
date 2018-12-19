package org.digidoc4j;

import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public interface ContainerValidationResult extends SignatureValidationResult {

  /**
   * Get list container related errors.
   *
   * DDOC returns a list of errors encountered when validating meta data
   * ASIC returns a list of errors encountered when opening the container
   *
   * @return List of exceptions
   */
  List<DigiDoc4JException> getContainerErrors();

}
