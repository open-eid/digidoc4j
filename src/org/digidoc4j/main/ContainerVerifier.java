/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.main;

import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.impl.ddoc.DDocSignature;
import org.digidoc4j.impl.ddoc.ValidationResultForDDoc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.digidoc.CertValue;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocGenFactory;

public class ContainerVerifier {

  private final static Logger logger = LoggerFactory.getLogger(ContainerVerifier.class);
  private static final String ANSI_RED = "[31m";
  private static final String ANSI_RESET = "[0m";
  private boolean verboseMode;
  private boolean showWarnings;

  public ContainerVerifier(CommandLine commandLine) {
    verboseMode = commandLine.hasOption("verbose");
    showWarnings = commandLine.hasOption("warnings");
  }

  public void verify(Container container) {
    ValidationResult validationResult = container.validate();

    List<DigiDoc4JException> exceptions = validationResult.getContainerErrors();
    boolean isDDoc = StringUtils.equalsIgnoreCase("DDOC", container.getType());
    for (DigiDoc4JException exception : exceptions) {
      if (isDDoc && isWarning(((DDocContainer) container).getFormat(), exception))
        System.out.println("	Warning: " + exception.toString());
      else
        System.out.println((isDDoc ? "	" : "	Error: ") + exception.toString());
    }

    if (isDDoc && (((ValidationResultForDDoc) validationResult).hasFatalErrors())) {
      throw new DigiDoc4JException("DDoc container has fatal errors");
    }

    List<Signature> signatures = container.getSignatures();
    if (signatures == null) {
      throw new SignatureNotFoundException();
    }

    for (Signature signature : signatures) {
      List<DigiDoc4JException> signatureValidationResult = signature.validateSignature().getErrors();
      if (signatureValidationResult.size() == 0) {
        System.out.println("Signature " + signature.getId() + " is valid");
      } else {
        System.out.println(ANSI_RED + "Signature " + signature.getId() + " is not valid" + ANSI_RESET);
        for (DigiDoc4JException exception : signatureValidationResult) {
          System.out.println((isDDoc ? "	" : "	Error: ")
              + exception.toString());
        }
      }
      if (isDDoc && isDDocTestSignature(signature)) {
        System.out.println("Signature " + signature.getId() + " is a test signature");
      }
    }

    showWarnings(validationResult);
    verboseMessage(validationResult.getReport());

    if(validationResult.isValid()) {
      logger.info("Validation was successful. Container is valid");
    } else {
      logger.info("Validation finished. Container is NOT valid!");
      throw new DigiDoc4JException("Container is NOT valid");
    }
  }

  private void verboseMessage(String message) {
    if (verboseMode)
      System.out.println(message);
  }

  private void showWarnings(ValidationResult validationResult) {
    if (showWarnings) {
      for (DigiDoc4JException warning : validationResult.getWarnings()) {
        System.out.println("Warning: " + warning.toString());
      }
    }
  }

  private boolean isWarning(String documentFormat, DigiDoc4JException exception) {
    int errorCode = exception.getErrorCode();
    return (errorCode == DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH
        || errorCode == DigiDocException.ERR_OLD_VER
        || errorCode == DigiDocException.ERR_TEST_SIGNATURE
        || errorCode == DigiDocException.WARN_WEAK_DIGEST
        || (errorCode == DigiDocException.ERR_ISSUER_XMLNS && !documentFormat.equals(SignedDoc.FORMAT_SK_XML)));
  }

  private static boolean isDDocTestSignature(Signature signature) {
    CertValue certValue = ((DDocSignature) signature).getCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
    if (certValue != null) {
      if (DigiDocGenFactory.isTestCard(certValue.getCert())) return true;
    }
    return false;
  }

}
