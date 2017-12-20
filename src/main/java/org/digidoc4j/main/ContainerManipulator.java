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

import static org.apache.commons.lang3.StringUtils.endsWithIgnoreCase;
import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;
import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.digidoc4j.Container.DocumentType.PADES;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataFile;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.asics.AsicSContainer;
import org.digidoc4j.impl.pades.PadesContainer;
import org.digidoc4j.signers.PKCS11SignatureToken;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.signers.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DigestAlgorithm;

/**
 * Class for managing digidoc4j-util parameters.
 */
public class ContainerManipulator {

  private static final Logger logger = LoggerFactory.getLogger(ContainerManipulator.class);

  private static final String EXTRACT_CMD = "extract";
  private CommandLine commandLine;
  private boolean fileHasChanged;

  public ContainerManipulator(CommandLine commandLine) {
    this.commandLine = commandLine;
  }

  public void processContainer(Container container) {
    logger.debug("Processing container");
    if (container instanceof PadesContainer) {
      verifyPadesContainer(container);
    } else {
      manipulateContainer(container);
      if (ASICS.equals(getContainerType(commandLine)) && isOptionsToSignAndAddFile()) {
        AsicSContainer asicSContainer = (AsicSContainer)container;
        verifyIfAllowedToAddSignature(asicSContainer);
        signAsicSContainer(asicSContainer);
      } else {
        signContainer(container);
      }
      verifyContainer(container);
    }
  }

  private boolean isOptionsToSignAndAddFile() {
    return commandLine.hasOption("add") || commandLine.hasOption("pkcs11") || commandLine.hasOption("pkcs12");
  }

  private void signAsicSContainer(AsicSContainer asicSContainer) {
    if (commandLine.hasOption("tst")) {
      signContainerWithTst(asicSContainer);
    } else {
      signContainer(asicSContainer);
    }
  }

  private void verifyIfAllowedToAddSignature(AsicSContainer asicSContainer) {
    if (asicSContainer.isTimestampTokenDefined()) {
      throw new DigiDoc4JException("This container has already timestamp. Should be no signatures in case of timestamped ASiCS container.");
    }
    if (!asicSContainer.getSignatures().isEmpty()){
      throw new DigiDoc4JException("This container is already signed. Should be only one signature in case of ASiCS container.");
    }
  }

  public Container openContainer(String containerPath) {
    Container.DocumentType type = getContainerType(commandLine);
    if (new File(containerPath).exists() || commandLine.hasOption("verify") || commandLine.hasOption("remove")) {
      logger.debug("Opening container " + containerPath);
      return ContainerOpener.open(containerPath);
    } else {
      logger.debug("Creating new " + type + "container " + containerPath);
      return ContainerBuilder.aContainer(type.name()).build();
    }
  }

  public void saveContainer(Container container, String containerPath) {
    if (fileHasChanged) {
      container.saveAsFile(containerPath);
      if (new File(containerPath).exists()) {
        logger.debug("Container has been successfully saved to " + containerPath);
      } else {
        logger.warn("Container was NOT saved to " + containerPath);
      }
    }
  }

  private void manipulateContainer(Container container) {
    if (commandLine.hasOption("add")) {
      String[] optionValues = commandLine.getOptionValues("add");
      container.addDataFile(optionValues[0], optionValues[1]);
      fileHasChanged = true;
    }

    if (commandLine.hasOption("remove")) {
      container.removeDataFile(commandLine.getOptionValue("remove"));
      fileHasChanged = true;
    }

    if (commandLine.hasOption(EXTRACT_CMD)) {
      logger.debug("Extracting data file");
      extractDataFile(container);
    }
  }

  /**
   * Gets container type for util logic
   *
   * @param commandLine
   * @return
   */
  public Container.DocumentType getContainerType(CommandLine commandLine) {
    if (equalsIgnoreCase(commandLine.getOptionValue("type"), "BDOC")) return BDOC;
    if (equalsIgnoreCase(commandLine.getOptionValue("type"), "ASICS")) return ASICS;
    if (equalsIgnoreCase(commandLine.getOptionValue("type"), "ASICE")) return ASICE;
    if (equalsIgnoreCase(commandLine.getOptionValue("type"), "DDOC")) return DDOC;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".bdoc")) return BDOC;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".asics")) return ASICS;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".scs")) return ASICS;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".asice")) return ASICE;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".sce")) return ASICE;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".ddoc")) return DDOC;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".pdf")) return PADES;
    return BDOC;
  }

  private void extractDataFile(Container container) {
    String[] optionValues = commandLine.getOptionValues(EXTRACT_CMD);
    String fileNameToExtract = optionValues[0];
    String extractPath = optionValues[1];
    boolean fileFound = false;
    for (DataFile dataFile : container.getDataFiles()) {
      if (equalsIgnoreCase(fileNameToExtract, dataFile.getName())) {
        logger.info("Extracting " + dataFile.getName() + " to " + extractPath);
        dataFile.saveAs(extractPath);
        fileFound = true;
      }
    }
    if (!fileFound) {
      throw new DigiDoc4JUtilityException(4, "Data file " + fileNameToExtract + " was not found in the container");
    }
  }

  private void signContainer(Container container) {
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);
    updateProfile(signatureBuilder);
    updateEncryptionAlgorithm(signatureBuilder);
    signWithPkcs12(container, signatureBuilder);
    signWithPkcs11(container, signatureBuilder);
  }

  private void updateProfile(SignatureBuilder signatureBuilder) {
    if (commandLine.hasOption("profile")) {
      String profile = commandLine.getOptionValue("profile");
      try {
        SignatureProfile signatureProfile = SignatureProfile.valueOf(profile);
        signatureBuilder.withSignatureProfile(signatureProfile);
      } catch (IllegalArgumentException e) {
        System.out.println("Signature profile \"" + profile + "\" is unknown and will be ignored");
      }
    }
  }

  private void updateEncryptionAlgorithm(SignatureBuilder signatureBuilder) {
    if (commandLine.hasOption("encryption")) {
      String encryption = commandLine.getOptionValue("encryption");
      EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.valueOf(encryption);
      signatureBuilder.withEncryptionAlgorithm(encryptionAlgorithm);
    }
  }

  private void signWithPkcs12(Container container, SignatureBuilder signatureBuilder) {
    if (commandLine.hasOption("pkcs12")) {
      String[] optionValues = commandLine.getOptionValues("pkcs12");
      SignatureToken pkcs12Signer = new PKCS12SignatureToken(optionValues[0], optionValues[1].toCharArray());
      Signature signature = invokeSigning(signatureBuilder, pkcs12Signer);
      container.addSignature(signature);
      fileHasChanged = true;
    }
  }

  private void signContainerWithTst(AsicContainer asicContainer) {
    if (commandLine.hasOption("tst") && !(commandLine.hasOption("pkcs12") || commandLine.hasOption("pkcs11"))) {
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
      if (commandLine.hasOption("datst")) {
        String digestAlgorithmStr = commandLine.getOptionValue("datst");
        if (StringUtils.isNotBlank(digestAlgorithmStr)) {
          digestAlgorithm = DigestAlgorithm.forName(digestAlgorithmStr);
        }
      }
      logger.info("Digest algorithm to calculate data file hash: " + digestAlgorithm.getName());
      if (commandLine.hasOption("add")) {
        if (asicContainer.getDataFiles().size() > 1){
          throw new DigiDoc4JException("Data file in container already exists. Should be only one data file in case of ASiCS container.");
        }
        String[] optionValues = commandLine.getOptionValues("add");
        DataFile dataFile = new DataFile(optionValues[0], optionValues[1]);
        DataFile tst = TimestampToken.generateTimestampToken(digestAlgorithm, dataFile);
        asicContainer.setTimeStampToken(tst);
        fileHasChanged = true;
      }
    }
  }

  private void signWithPkcs11(Container container, SignatureBuilder signatureBuilder) {
    if (commandLine.hasOption("pkcs11")) {
      String[] optionValues = commandLine.getOptionValues("pkcs11");
      String pkcs11ModulePath = optionValues[0];
      char[] pin = optionValues[1].toCharArray();
      int slotIndex = Integer.parseInt(optionValues[2]);
      SignatureToken pkcs11Signer = new PKCS11SignatureToken(pkcs11ModulePath, pin, slotIndex);
      Signature signature = invokeSigning(signatureBuilder, pkcs11Signer);
      container.addSignature(signature);
      fileHasChanged = true;
    }
  }

  private Signature invokeSigning(SignatureBuilder signatureBuilder, SignatureToken signatureToken) {
    return signatureBuilder.
        withSignatureToken(signatureToken).
        invokeSigning();
  }

  private void verifyContainer(Container container) {
    Path reports = null;
    if (commandLine.hasOption("reportDir")) {
      reports = Paths.get(commandLine.getOptionValue("reportDir"));
    }
    if (commandLine.hasOption("verify")) {
      ContainerVerifier verifier = new ContainerVerifier(commandLine);
      verifier.verify(container, reports);
    }
  }

  private void verifyPadesContainer(Container container) {
    ValidationResult validate = container.validate();
    if (!validate.isValid()) {
      String report = validate.getReport();
      throw new DigiDoc4JException("Pades container has errors" + report);
    } else {
      logger.info("Container is valid:" + validate.isValid());
    }
  }

}
