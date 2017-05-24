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
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;

import java.io.File;
import java.io.IOException;

import org.apache.commons.cli.CommandLine;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataFile;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS11SignatureToken;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ContainerManipulator {

  private final static Logger logger = LoggerFactory.getLogger(ContainerManipulator.class);

  private static final String EXTRACT_CMD = "extract";
  private CommandLine commandLine;
  private boolean fileHasChanged;

  public ContainerManipulator(CommandLine commandLine) {
    this.commandLine = commandLine;
  }

  public void processContainer(Container container) {
    logger.debug("Processing container");
    manipulateContainer(container);
    signContainer(container);
    verifyContainer(container);
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

  public Container.DocumentType getContainerType(CommandLine commandLine) {
    if (equalsIgnoreCase(commandLine.getOptionValue("type"), "BDOC")) return BDOC;
    if (equalsIgnoreCase(commandLine.getOptionValue("type"), "DDOC")) return DDOC;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".bdoc")) return BDOC;
    if (endsWithIgnoreCase(commandLine.getOptionValue("in"), ".ddoc")) return DDOC;
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
      //TODO test new constructor
      SignatureToken pkcs12Signer = new PKCS12SignatureToken(optionValues[0], optionValues[1].toCharArray());
      Signature signature = invokeSigning(signatureBuilder, pkcs12Signer);
      container.addSignature(signature);
      fileHasChanged = true;
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
    if (commandLine.hasOption("verify")) {
      ContainerVerifier verifier = new ContainerVerifier(commandLine);
      verifier.verify(container);
    }
  }
}
