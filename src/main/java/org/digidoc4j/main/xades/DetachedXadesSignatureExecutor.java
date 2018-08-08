package org.digidoc4j.main.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DetachedXadesSignatureBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.DigestDataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.main.DigiDoc4JUtilityException;
import org.digidoc4j.main.ExecutionCommand;
import org.digidoc4j.main.ExecutionOption;
import org.digidoc4j.signers.PKCS11SignatureToken;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Executor for managing detached XadES signatures.
 */
public class DetachedXadesSignatureExecutor {

  private static final Logger LOGGER = LoggerFactory.getLogger(DetachedXadesSignatureExecutor.class);

  private final DetachedXadesExecutionContext context;

  public DetachedXadesSignatureExecutor(CommandLine commandLine) {
    DetachedXadesExecutionContext context = DetachedXadesExecutionContext.of(commandLine, checkSupportedFunctionality(commandLine));
    this.context = context;
  }

  public boolean hasCommand() {
    return this.context.getCommand() != null;
  }

  public void executeCommand() {
    if (this.hasCommand()) {
      for (ExecutionOption option : context.getCommand().getMandatoryOptions()) {
        switch (option) {
          case DIGEST_FILE:
            addDigestFile();
            break;
          case PKCS11:
            context.setSignatureToken(loadPKCS11Token());
            break;
          case PKCS12:
            context.setSignatureToken(loadPKCS12Token());
            break;
          case XADES_OUTPUT_PATH:
            saveSignature();
          case XADES_INPUT_PATH:
            context.setSignature(openSignature());
          default:
            LOGGER.warn("No option <{}> implemented", option);
        }
      }
    } else {
      throw new DigiDoc4JException("No command to execute");
    }
  }

  private void saveSignature() {
    context.setSignature(sign());
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.XADES_OUTPUT_PATH.getName());
    try {
      FileUtils.writeByteArrayToFile(new File(values[0]), context.getSignature().getAdESSignature());
    } catch (IOException e) {
      throw new DigiDoc4JException("Error writing XadES signature to specified file");
    }
  }

  private Signature openSignature() {
    try {
      String[] values = context.getCommandLine().getOptionValues(ExecutionOption.XADES_INPUT_PATH.getName());
      byte[] xadesSignature = IOUtils.toByteArray(new FileInputStream(values[0]));
      Signature signature = DetachedXadesSignatureBuilder
          .withConfiguration(new Configuration())
          .withDataFile(context.getDigestDataFile())
          .openAdESSignature(xadesSignature);
      ValidationResult result = signature.validateSignature();
      result.getErrors();
      if (result.isValid()) {
        LOGGER.info("Signature " + signature.getId() + " is valid");
      } else {
        LOGGER.info("Signature " + signature.getId() + " is invalid, errors:");
        for (DigiDoc4JException error : result.getErrors()) {
          LOGGER.error(error.getMessage());
        }
      }
      return signature;
    } catch (IOException e) {
      throw new DigiDoc4JException("Error reading XadES signature from specified file");
    }
  }

  private Signature sign() {
    setDigestAlgorithm();
    setSignatureProfile();
    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(context.getDigestDataFile())
        .withSignatureToken(context.getSignatureToken())
        .withSignatureDigestAlgorithm(context.getDigestAlgorithm())
        .invokeSigning();
    return signature;
  }

  private void addDigestFile() {
    LOGGER.debug("Adding digest data file ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.DIGEST_FILE.getName());
    DigestDataFile digestDataFile = new DigestDataFile(values[0], DigestAlgorithm.SHA256,
        Base64.decodeBase64(values[1]));
    context.setDigestDataFile(digestDataFile);
  }

  private SignatureToken loadPKCS11Token() {
    LOGGER.debug("Loading PKCS11 token ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.PKCS11.getName());
    try {
      return new PKCS11SignatureToken(values[0], values[1].toCharArray(), Integer.parseInt(values[2]), values[3]);
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to load PKCS11 token <%s, %s, %s>", values[0], values[1], values[2]));
    }
  }

  private SignatureToken loadPKCS12Token() {
    LOGGER.debug("Loading PKCS12 token ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.PKCS12.getName());
    try {
      return new PKCS12SignatureToken(values[0], values[1].toCharArray());
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to load PKCS12 token <%s, %s>", values[0], values[1]));
    }
  }

  private void setDigestAlgorithm() {
    if (context.getCommandLine().hasOption("datst")) {
      String digestAlgorithmStr = context.getCommandLine().getOptionValue("datst");
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.findByAlgorithm(digestAlgorithmStr);
      if (digestAlgorithm != null) {
        context.setDigestAlgorithm(digestAlgorithm);
      }
    }
  }

  private void setSignatureProfile() {
    if (context.getCommandLine().hasOption("profile")) {
      String profileStr = context.getCommandLine().getOptionValue("profile");
      SignatureProfile profile = SignatureProfile.findByProfile(profileStr);
      if (profile != null) {
        context.setProfile(profile);
      }
    }
  }

  private ExecutionCommand checkSupportedFunctionality(CommandLine commandLine) {
    for (ExecutionCommand command : ExecutionCommand.values()) {
      if (hasOptionsMatch(commandLine, command.getMandatoryOptions())) {
        for (ExecutionOption option : command.getMandatoryOptions()) {
          checkOption(option, commandLine, true);
        }
        return command;
      }
    }
    return null;
  }

  private static boolean hasOptionsMatch(CommandLine commandLine, List<ExecutionOption> commands) {
    int matchCount = 0;
    for (ExecutionOption command : commands) {
      if (commandLine.hasOption(command.getName())) {
        matchCount++;
      }
    }
    return matchCount == commands.size();
  }

  private static void checkOption(ExecutionOption option, CommandLine commandLine, boolean mandatory) {
    if (commandLine.hasOption(option.getName())) {
      int count = 0;
      try {
        count = commandLine.getOptionValues(option.getName()).length;
      } catch (NullPointerException ignore) {
      }
      if (count != option.getCount()) {
        throw new DigiDoc4JUtilityException(String.format("Option <%s> parameter count is invalid", option));
      }
    } else {
      if (mandatory) {
        throw new DigiDoc4JUtilityException(String.format("Option <%s> is mandatory", option));
      }
    }
  }

}
