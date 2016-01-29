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
import org.digidoc4j.impl.bdoc.BDocValidationResult;
import org.digidoc4j.impl.bdoc.manifest.ManifestParser;
import org.digidoc4j.impl.bdoc.manifest.ManifestValidator;

import eu.europa.esig.dss.DSSDocument;

public class BDocContainerValidator implements Serializable {

  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<Signature> signatures;
  private AsicParseResult containerParseResult;

  public BDocContainerValidator(List<Signature> signatures, AsicParseResult containerParseResult) {
    this.signatures = signatures;
    this.containerParseResult = containerParseResult;
  }

  public ValidationResult validate() {
    BDocValidationResult result = new BDocValidationResult();

    List<DigiDoc4JException> manifestErrors = findManifestErrors();
    errors.addAll(manifestErrors);

    for (Signature signature : signatures) {
      List<DigiDoc4JException> signatureErrors = signature.validate();
      errors.addAll(signatureErrors);
    }

    result.setErrors(errors);
    return result;
  }

  private List<DigiDoc4JException> findManifestErrors() {
    if (containerParseResult == null || containerParseResult.getManifestParser() == null) {
      return Collections.emptyList();
    }
    List<DigiDoc4JException> manifestExceptions = new ArrayList<>();
    ManifestParser manifestParser = containerParseResult.getManifestParser();
    List<DSSDocument> detachedContents = containerParseResult.getDetachedContents();
    List<String> manifestErrors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    for (String manifestError : manifestErrors) {
      manifestExceptions.add(new DigiDoc4JException(manifestError));
    }
    return manifestExceptions;
  }
}
