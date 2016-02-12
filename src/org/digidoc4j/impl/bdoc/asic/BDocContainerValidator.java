/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.asic;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.bdoc.BDocValidationResult;
import org.digidoc4j.impl.bdoc.manifest.ManifestParser;
import org.digidoc4j.impl.bdoc.manifest.ManifestValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

public class BDocContainerValidator implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(BDocContainerValidator.class);
  private List<DigiDoc4JException> errors = new ArrayList<>();
  private AsicParseResult containerParseResult;
  private boolean validateManifest;

  public BDocContainerValidator() {
    validateManifest = false;
  }

  public BDocContainerValidator(AsicParseResult containerParseResult) {
    this.containerParseResult = containerParseResult;
    validateManifest = true;
  }

  public ValidationResult validate(List<Signature> signatures) {
    BDocValidationResult result = new BDocValidationResult();

    for (Signature signature : signatures) {
      List<DigiDoc4JException> signatureErrors = signature.validate();
      errors.addAll(signatureErrors);
    }

    List<DigiDoc4JException> manifestErrors = findManifestErrors(signatures);
    errors.addAll(manifestErrors);

    result.setErrors(errors);
    return result;
  }

  public void setValidateManifest(boolean validateManifest) {
    this.validateManifest = validateManifest;
  }

  private List<DigiDoc4JException> findManifestErrors(List<Signature> signatures) {
    if (!validateManifest || containerParseResult == null) {
      return Collections.emptyList();
    }
    ManifestParser manifestParser = containerParseResult.getManifestParser();
    if (manifestParser == null || !manifestParser.containsManifestFile()) {
      logger.error("Container is missing manifest.xml");
      List<DigiDoc4JException> manifestExceptions = new ArrayList<>();
      manifestExceptions.add(new UnsupportedFormatException("Container does not contain a manifest file"));
      return manifestExceptions;
    }
    List<DigiDoc4JException> manifestExceptions = new ArrayList<>();
    List<DSSDocument> detachedContents = containerParseResult.getDetachedContents();
    List<String> manifestErrors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    for (String manifestError : manifestErrors) {
      manifestExceptions.add(new DigiDoc4JException(manifestError));
    }
    return manifestExceptions;
  }
}
