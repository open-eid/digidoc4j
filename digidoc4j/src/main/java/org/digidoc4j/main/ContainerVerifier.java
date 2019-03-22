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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Path;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.impl.asic.tsl.TslManager;
import org.digidoc4j.impl.ddoc.DDocSignatureValidationResult;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.impl.ddoc.DDocSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.digidoc4j.ddoc.CertValue;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.factory.DigiDocGenFactory;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

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

  /**
   * Method for validation directly with DSS classes (option -v2).
   * The goal is to generate DSS reports.
   *
   * @param container Validation object.
   * @param reportsDir Directory where to save reports.
   */
  public void verifyDirectDss(Container container, Path reportsDir) {
    boolean isDDoc = StringUtils.equalsIgnoreCase("DDOC", container.getType());
    if (isDDoc) {
      logger.info("Validation canceled. Option -v2 is not working with DDOC container.");
      throw new DigiDoc4JException("Option -v2 is not working with DDOC container");
    }
    Configuration configuration = Configuration.getInstance();
    TslManager tslManager = new TslManager(configuration);
    TSLCertificateSource certificateSource = tslManager.getTsl();
    configuration.setTSL(certificateSource);
    DSSDocument document = new InMemoryDocument(container.saveAsStream());
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
    SKCommonCertificateVerifier verifier = new SKCommonCertificateVerifier();
    verifier.setOcspSource(OCSPSourceBuilder.anOcspSource().withConfiguration(configuration).build());
    verifier.setTrustedCertSource(configuration.getTSL());
    verifier.setDataLoader(SkDataLoader.ocsp(configuration));
    validator.setCertificateVerifier(verifier);
    Reports reports = validator.validateDocument();
    if (reportsDir != null) {
      try {
        byte[] bytes = reports.getXmlDiagnosticData().getBytes("UTF-8");
        DSSUtils.saveToFile(bytes, new File(reportsDir + File.separator + "validationDiagnosticData.xml"));
        logger.info("Validation diagnostic data report is generated");
      } catch (UnsupportedEncodingException e) {
        logger.info(e.getMessage());
      } catch (IOException e) {
        logger.info(e.getMessage());
      }
      try {
        byte[] bytes = reports.getXmlSimpleReport().getBytes("UTF-8");
        DSSUtils.saveToFile(bytes, new File(reportsDir + File.separator + "validationSimpleReport.xml"));
        logger.info("Validation simple report is generated");
      } catch (UnsupportedEncodingException e) {
        logger.info(e.getMessage());
      } catch (IOException e) {
        logger.info(e.getMessage());
      }
      try {
        byte[] bytes = reports.getXmlDetailedReport().getBytes("UTF-8");
        DSSUtils.saveToFile(bytes, new File(reportsDir + File.separator + "validationDetailReport.xml"));
        logger.info("Validation detailed report is generated");
      } catch (UnsupportedEncodingException e) {
        logger.info(e.getMessage());
      } catch (IOException e) {
        logger.info(e.getMessage());
      }
    }
    boolean isValid = true;
    for (String signatureId : reports.getSimpleReport().getSignatureIdList()) {
      isValid = isValid && reports.getSimpleReport().isSignatureValid(signatureId);
    }
    if (isValid) {
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
