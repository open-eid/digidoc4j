package org.digidoc4j.main.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.DigiDoc4JException;
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
            addDigestFiles();
            break;
          case PKCS11:
            context.setSignatureToken(loadPKCS11Token());
            break;
          case PKCS12:
            context.setSignatureToken(loadPKCS12Token());
            break;
          case XADES_OUTPUT_PATH:
            saveSignature();
            break;
          case XADES_INPUT_PATH:
            context.setSignature(openSignature());
            break;
          case DETACHED_XADES:
            break;
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
      DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
          .withConfiguration(new Configuration());
      for (DigestDataFile digestDataFile : context.getDigestDataFiles()) {
        signatureBuilder.withDataFile(digestDataFile);
      }
      Signature signature = signatureBuilder.openAdESSignature(xadesSignature);
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
    Configuration conf = new Configuration();
    useAiaOcsp(conf);
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder.withConfiguration(conf);
    for (DigestDataFile digestDataFile : context.getDigestDataFiles()) {
      signatureBuilder.withDataFile(digestDataFile);
    }
    Signature signature = signatureBuilder.withSignatureToken(context.getSignatureToken())
        .withSignatureDigestAlgorithm(context.getDigestAlgorithm())
        .withSignatureProfile(context.getProfile())
        .invokeSigning();
    return signature;
  }

  private void addDigestFiles() {
    LOGGER.debug("Adding digest data file(s) ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.DIGEST_FILE.getName());
    if (values.length % 2 != 0) {
      throw new DigiDoc4JException("Invalid count of digest file(s) parameters!");
    }
    for (int i = 0; i < values.length; i+=2) {
      String name = values[i];
      String base64EncodedDigest = values[i+1];
      LOGGER.debug("Adding digest data file with name: " + name + " ; and base64 encoded digest: " + base64EncodedDigest);
      addDigestFile(name, base64EncodedDigest);
    }
  }

  private void addDigestFile(String name, String base64EncodedDigest) {
    DigestDataFile digestDataFile = new DigestDataFile(name, DigestAlgorithm.SHA256,
        Base64.decodeBase64(base64EncodedDigest));
    context.addDigestDataFile(digestDataFile);
  }

  private void useAiaOcsp(Configuration configuration) {
    if (this.context.getCommandLine().hasOption("aiaocsp")) {
      configuration.setPreferAiaOcsp(true);
    }
  }

  private SignatureToken loadPKCS11Token() {
    LOGGER.debug("Loading PKCS11 token ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.PKCS11.getName());
    try {
      if (values.length > 3) {
        return new PKCS11SignatureToken(values[0], values[1].toCharArray(), Integer.parseInt(values[2]), values[3]);
      } else {
        return new PKCS11SignatureToken(values[0], values[1].toCharArray(), Integer.parseInt(values[2]));
      }
    } catch (Exception e) {
      throw new DigiDoc4JException("Unable to load PKCS11 token: " + Arrays.toString(values), e);
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

}
