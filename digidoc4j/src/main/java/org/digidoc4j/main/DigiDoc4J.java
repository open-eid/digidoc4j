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
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.digidoc4j.Container;
import org.digidoc4j.Version;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.main.xades.DetachedXadesSignatureExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;

/**
 * Client commandline tool for DigiDoc4J library.
 */
public final class DigiDoc4J {

  private static final Logger logger = LoggerFactory.getLogger(DigiDoc4J.class);

  private DigiDoc4J() {
  }

  /**
   * Utility main method
   *
   * @param args command line arguments
   */
  public static void main(String[] args) {
    try {
      if (System.getProperty("digidoc4j.mode") == null) {
        System.setProperty("digidoc4j.mode", "PROD");
      }
      DigiDoc4J.run(args);
    } catch (DigiDoc4JUtilityException e) {
      if (DigiDoc4J.logger.isDebugEnabled()) {
        DigiDoc4J.logger.error("Utility error", e);
      } else {
        DigiDoc4J.logger.error("Utility error (please apply DEBUG level for stacktrace): {}", e.getMessage());
      }
      System.err.print(e.getMessage());
      System.exit(e.getErrorCode());
    } catch (Exception e) {
      if (DigiDoc4J.logger.isDebugEnabled()) {
        DigiDoc4J.logger.error("Utility error", e);
      } else {
        DigiDoc4J.logger.error("Utility error (please apply DEBUG level for stacktrace): {}", e.getMessage());
      }
      System.err.print(e.getMessage());
      System.exit(1);
    }
    logger.info("Finished running utility method");
    System.exit(0);
  }

  /**
   * Checks is DigiDoc4JException predefined as warning for DDOC
   *
   * @param documentFormat format SignedDoc
   * @param exception      error to check
   * @return is this exception warning for DDOC utility program
   * @see SignedDoc
   */
  public static boolean isWarning(String documentFormat, DigiDoc4JException exception) {
    int errorCode = exception.getErrorCode();
    return (errorCode == DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH
        || errorCode == DigiDocException.ERR_OLD_VER
        || errorCode == DigiDocException.ERR_TEST_SIGNATURE
        || errorCode == DigiDocException.WARN_WEAK_DIGEST
        || (errorCode == DigiDocException.ERR_ISSUER_XMLNS && !documentFormat.equals(SignedDoc.FORMAT_SK_XML)));
  }

  /*
   * RESTRICTED METHODS
   */

  private static void run(String[] args) {
    Options options = DigiDoc4J.createParameters();
    try {
      CommandLine commandLine = new DefaultParser().parse(options, args);
      if (commandLine.hasOption("version")) {
        DigiDoc4J.showVersion();
      }
      boolean execute = DigiDoc4J.shouldManipulateContainer(commandLine) || DigiDoc4J.shouldOperateWithDetachedXades(commandLine);
      if (execute) {
        DigiDoc4J.execute(commandLine);
      }
      if (!commandLine.hasOption("version") && !execute) {
        DigiDoc4J.showUsage(options);
      }
    } catch (ParseException e) {
      DigiDoc4J.showUsage(options);
      throw new DigiDoc4JUtilityException(2, new RuntimeException("Problem with given parameters", e));
    }
  }

  private static void showUsage(Options options) {
    new HelpFormatter().printHelp("digidoc4j/" + Version.VERSION, options);
  }

  private static boolean shouldManipulateContainer(CommandLine commandLine) {
    return commandLine.hasOption(ExecutionOption.DTS.getName()) || commandLine.hasOption(
        ExecutionOption.IN.getName()) || DigiDoc4J.isMultipleContainerCreation(commandLine);
  }

  private static boolean shouldOperateWithDetachedXades(CommandLine commandLine) {
    return commandLine.hasOption(ExecutionOption.DETACHED_XADES.getName());
  }

  private static void execute(CommandLine commandLine) {
    try {
      if (DigiDoc4J.isDetachedXades(commandLine)) {
        DetachedXadesSignatureExecutor xadesCreator = new DetachedXadesSignatureExecutor(commandLine);
        xadesCreator.executeCommand();
      } else {
        CommandLineExecutor executor = new CommandLineExecutor(
            ExecutionContext.of(commandLine, DigiDoc4J.checkSupportedFunctionality(commandLine)));
        if (executor.hasCommand()) {
          executor.executeCommand();
        } else if (commandLine.hasOption(ExecutionOption.IN.getName())) {
          String containerPath = commandLine.getOptionValue(ExecutionOption.IN.getName());
          Container container = executor.openContainer(containerPath);
          executor.processContainer(container);
          executor.saveContainer(container, containerPath);
        } else if (DigiDoc4J.isMultipleContainerCreation(commandLine)) {
          MultipleContainersExecutor containersCreator = new MultipleContainersExecutor(commandLine);
          containersCreator.execute();
        }
      }
    } catch (DigiDoc4JUtilityException e) {
      throw e;
    } catch (DigiDoc4JException e) {
      throw new DigiDoc4JUtilityException(1, e);
    }
  }

  private static ExecutionCommand checkSupportedFunctionality(CommandLine commandLine) {
    if (commandLine.hasOption(ExecutionOption.DTS.getName())) {
      for (ExecutionCommand command : ExecutionCommand.values()) {
        if (DigiDoc4J.hasOptionsMatch(commandLine, command.getMandatoryOptions())) {
          for (ExecutionOption option : command.getMandatoryOptions()) {
            DigiDoc4J.checkOption(option, commandLine, true);
          }
          return command;
        }
      }
    } else {
      DigiDoc4J.checkOption(ExecutionOption.ADD, commandLine);
      DigiDoc4J.checkOption(ExecutionOption.EXTRACT, commandLine);
      if (commandLine.hasOption("pkcs11") && commandLine.hasOption("pkcs12")) {
        throw new DigiDoc4JUtilityException(5, "Cannot sign with both PKCS#11 and PKCS#12");
      }
    }
    return null;
  }

  static boolean hasOptionsMatch(CommandLine commandLine, List<ExecutionOption> commands) {
    int matchCount = 0;
    for (ExecutionOption command : commands) {
      if (commandLine.hasOption(command.getName())) {
        matchCount++;
      }
    }
    return matchCount == commands.size();
  }

  private static void checkOption(ExecutionOption option, CommandLine commandLine) {
    DigiDoc4J.checkOption(option, commandLine, false);
  }

  static void checkOption(ExecutionOption option, CommandLine commandLine, boolean mandatory) {
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

  private static boolean isMultipleContainerCreation(CommandLine commandLine) {
    return commandLine.hasOption("inputDir") && commandLine.hasOption("outputDir");
  }

  private static boolean isDetachedXades(CommandLine commandLine) {
    return commandLine.hasOption("xades");
  }

  private static Options createParameters() {
    Options options = new Options();
    options.addOption("v", "verify", false, "verify input file");
    options.addOption("verbose", "verbose", false, "verbose output");
    options.addOption("w", "warnings", false, "show warnings");
    options.addOption("version", "version", false, "show version");
    options.addOption("tst", "timestamp", false, "adds timestamp token to container");
    options.addOption("err", "showerrors", false, "show container errors");
    options.addOption("aiaocsp", "aiaocsp", false, "prefer AIA OCSP in case of LT,LTA signature profiles");
    options.addOption(DigiDoc4J.type());
    options.addOption(DigiDoc4J.inputFile());
    options.addOption(DigiDoc4J.inputDir());
    options.addOption(DigiDoc4J.outputDir());
    options.addOption(DigiDoc4J.addFile());
    options.addOption(DigiDoc4J.removeFile());
    options.addOption(DigiDoc4J.pkcs12Sign());
    options.addOption(DigiDoc4J.pkcs11Sign());
    options.addOption(DigiDoc4J.signatureProfile());
    options.addOption(DigiDoc4J.encryptionAlgorithm());
    options.addOption(DigiDoc4J.mimeType());
    options.addOption(DigiDoc4J.extractDataFile());
    options.addOption(DigiDoc4J.reportsDir());
    options.addOption(DigiDoc4J.tstDigestAlgorihm());
    options.addOption(DigiDoc4J.signingDataFile());
    options.addOption(DigiDoc4J.signatureFile());
    options.addOption(DigiDoc4J.certificateFile());

    options.addOption(DigiDoc4J.detachedXades());
    options.addOption(DigiDoc4J.addDigestFile());
    options.addOption(DigiDoc4J.xadesOutputPath());
    options.addOption(DigiDoc4J.xadesInputPath());
    return options;
  }

  private static Option signingDataFile() {
    return OptionBuilder.withArgName("path").hasArg().withDescription("specifies location path of signing data file")
        .withLongOpt("signingDataFile").create(ExecutionOption.DTS.getName());
  }

  private static Option signatureFile() {
    return OptionBuilder.withArgName("path").hasArg().withDescription("specifies location path of signature file")
        .withLongOpt("signatureFile").create(ExecutionOption.SIGNATURE.getName());
  }

  private static Option certificateFile() {
    return OptionBuilder.withArgName("path").hasArg().withDescription(
        "specifies loaction path of public certificate file")
        .withLongOpt("certificateFile").create(ExecutionOption.CERTIFICATE.getName());
  }

  private static Option tstDigestAlgorihm() {
    return OptionBuilder.withArgName("digestAlgorithm").hasArgs()
        .withDescription("sets method to calculate datafile hash for timestamp token. Default: SHA256").create("datst");
  }

  private static Option signatureProfile() {
    return OptionBuilder.withArgName("signatureProfile").hasArg()
        .withDescription("sets signature profile. Profile can be B_BES, LT, LT_TM or LTA").withLongOpt(
            "profile").create("p");
  }

  private static Option encryptionAlgorithm() {
    return OptionBuilder.withArgName("encryptionAlgorithm").hasArg()
        .withDescription("sets the encryption algorithm (RSA/ECDSA).").withLongOpt("encryption").create("e");
  }

  private static Option pkcs12Sign() {
    return OptionBuilder.withArgName("pkcs12Keystore password").hasArgs(2)
        .withDescription("sets pkcs12 keystore and keystore password").create("pkcs12");
  }

  private static Option pkcs11Sign() {
    return OptionBuilder.withArgName("pkcs11ModulePath pin slot label").hasOptionalArgs(4)
        .withDescription("sets pkcs11 module path, pin(password), slot index and (optionally) keypair label").create
            ("pkcs11");
  }

  private static Option removeFile() {
    return OptionBuilder.withArgName("file").hasArg().withDescription("removes file from container").create("remove");
  }

  private static Option addFile() {
    return OptionBuilder.withArgName("file mime-type").hasArgs(2)
        .withDescription("adds file specified with mime type to container").create("add");
  }

  private static Option inputFile() {
    return OptionBuilder.withArgName("file").hasArg().withDescription("opens or creates container").create("in");
  }

  private static Option inputDir() {
    return OptionBuilder.withArgName("inputDir").hasArg()
        .withDescription("directory path containing data files to sign").create("inputDir");
  }

  private static Option reportsDir() {
    return OptionBuilder.withArgName("reportDir").hasArg().withDescription("directory path for validation reports")
        .withLongOpt("reportDir").create("r");
  }

  private static Option mimeType() {
    return OptionBuilder.withArgName("mimeType").hasArg().withDescription(
        "specifies input file mime type when using inputDir")
        .create("mimeType");
  }

  private static Option outputDir() {
    return OptionBuilder.withArgName("outputDir").hasArg().withDescription("directory path where containers are saved")
        .create("outputDir");
  }

  private static Option type() {
    return OptionBuilder.withArgName("type").hasArg()
        .withDescription("sets container type. Types can be DDOC, BDOC, ASICE or ASICS").withLongOpt("type").create(
            "t");
  }

  private static Option extractDataFile() {
    return OptionBuilder.withArgName("fileName destination").hasArgs(2)
        .withDescription("extracts the file from the container to the specified destination").create(
            ExecutionOption.EXTRACT.getName());
  }

  private static void showVersion() {
    System.out.println("DigiDoc4j version " + Version.VERSION);
  }

  private static Option detachedXades() {
    return OptionBuilder.hasArg(false)
        .withDescription("operates with detached XadES").create(ExecutionOption.DETACHED_XADES.getName());
  }

  private static Option addDigestFile() {
    return OptionBuilder.withArgName("name digest mimeType").hasArgs(ExecutionOption.DIGEST_FILE.getCount())
        .withDescription("sets digest (in base64) data file for detached XadES").create(ExecutionOption.DIGEST_FILE
            .getName());
  }

  private static Option xadesOutputPath() {
    return OptionBuilder.withArgName("path").hasArg()
        .withDescription("sets the destination where detached XadES signature will be saved").create(ExecutionOption
            .XADES_OUTPUT_PATH
            .getName());
  }

  private static Option xadesInputPath() {
    return OptionBuilder.withArgName("path").hasArg()
        .withDescription("sets the source where detached XadES signature will read from").create(ExecutionOption
            .XADES_INPUT_PATH
            .getName());
  }

}
