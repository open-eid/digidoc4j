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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.ddoc.CertValue;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.factory.DigiDocGenFactory;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.impl.ddoc.DDocSignature;
import org.digidoc4j.impl.ddoc.DDocSignatureValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;

/**
 * Container verifying functionality for digidoc4j-util.
 */
public class ContainerVerifier {

  private static final Logger logger = LoggerFactory.getLogger(ContainerVerifier.class);
  private static final String ANSI_RED = "[31m";
  private static final String ANSI_RESET = "[0m";
  private boolean verboseMode;
  private boolean showWarnings;

  /**
   * Constructor
   * @param commandLine Given parameters
   */
  public ContainerVerifier(CommandLine commandLine) {
    verboseMode = commandLine.hasOption("verbose");
    showWarnings = commandLine.hasOption("warnings");
  }

  private static boolean isDDocTestSignature(Signature signature) {
    CertValue certValue = ((DDocSignature) signature).getCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
    if (certValue != null) {
      if (DigiDocGenFactory.isTestCard(certValue.getCert())) return true;
    }
    return false;
  }

  /**
   * Method for verifying, old BDOC style.
   * @param container Given container to verify.
   * @param reports Directory where to save reports.
   */
  public void verify(Container container, Path reports) {
    verify(container, reports, false);
  }

  /**
   * Method for verifying, old BDOC style and returning validation result.
   * @param container Given container to verify.
   * @param reports Directory where to save reports.
   * @param isReportNeeded Define if need report
   * @return ValidationResult
   */
  public ContainerValidationResult verify(Container container, Path reports, boolean isReportNeeded) {

    ContainerValidationResult containerValidationResult = container.validate();
    if (reports != null) {
      containerValidationResult.saveXmlReports(reports);
    }
    List<DigiDoc4JException> exceptions = containerValidationResult.getContainerErrors();
    boolean isDDoc = StringUtils.equalsIgnoreCase("DDOC", container.getType());
    for (DigiDoc4JException exception : exceptions) {
      if (isDDoc && isWarning(((DDocContainer) container).getFormat(), exception))
        System.out.println(" Warning: " + exception.toString());
      else
        System.out.println((isDDoc ? " " : " Error: ") + exception.toString());
    }

    if (isDDoc && (((DDocSignatureValidationResult) containerValidationResult).hasFatalErrors())) {
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
          System.out.println((isDDoc ? " " : " Error: ")
              + exception.toString());
        }
      }
      if (isDDoc && isDDocTestSignature(signature)) {
        System.out.println("Signature " + signature.getId() + " is a test signature");
      }
    }

    showWarnings(containerValidationResult);
    verboseMessage(containerValidationResult.getReport());

    if (containerValidationResult.isValid()) {
      logger.info("Validation was successful. Container is valid");
    } else {
      logger.info("Validation finished. Container is NOT valid!");
      if (!isReportNeeded) {
        throw new DigiDoc4JException("Container is NOT valid");
      }
    }
    return containerValidationResult;
  }

  private void verboseMessage(String message) {
    if (verboseMode)
      System.out.println(message);
  }

  private void showWarnings(SignatureValidationResult signatureValidationResult) {
    if (showWarnings) {
      for (DigiDoc4JException warning : signatureValidationResult.getWarnings()) {
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

}
