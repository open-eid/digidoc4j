/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.asice.bdoc;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.digidoc4j.Configuration;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicValidationReportBuilder;
import org.digidoc4j.impl.asic.AsicValidationResult;
import org.digidoc4j.impl.asic.asice.AsicEContainerValidator;
import org.digidoc4j.impl.asic.manifest.ManifestErrorMessage;
import org.digidoc4j.impl.asic.manifest.ManifestParser;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidationData;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidationTask;
import org.digidoc4j.impl.asic.xades.validation.ThreadPoolManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

/**
 * BDOC container validator
 */
public class BDocContainerValidator extends AsicEContainerValidator implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(BDocContainerValidator.class);

  /**
   * @param configuration configuration
   */
  public BDocContainerValidator(Configuration configuration) {
    super(configuration);
  }

  /**
   * @param containerParseResult ASIC container parse result
   * @param configuration configuration
   */
  public BDocContainerValidator(AsicParseResult containerParseResult, Configuration configuration) {
    super(containerParseResult, configuration);
  }

  /**
   * @param signatures list of signatures
   * @return validation result
   */
  public ValidationResult validate(List<Signature> signatures) {
    logger.debug("Validating BDOC container");
    validateSignatures(signatures);
    extractManifestErrors(signatures);
    AsicValidationResult result = createValidationResult();
    logger.info("Is container valid: " + result.isValid());
    return result;
  }
}
