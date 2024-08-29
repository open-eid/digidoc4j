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
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.digidoc4j.Container;
import org.digidoc4j.Version;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.main.xades.DetachedXadesSignatureExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

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
    System.exit(executeAndReturnExitStatus(args));
  }

  static int executeAndReturnExitStatus(String[] args) {
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
      return e.getErrorCode();
    } catch (Exception e) {
      if (DigiDoc4J.logger.isDebugEnabled()) {
        DigiDoc4J.logger.error("Utility error", e);
      } else {
        DigiDoc4J.logger.error("Utility error (please apply DEBUG level for stacktrace): {}", e.getMessage());
      }
      System.err.print(e.getMessage());
      return 1;
    }
    logger.info("Finished running utility method");
    return 0;
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
    options.addOption("err", "showerrors", false, "show container errors [deprecated]");
    options.addOption("aiaocsp", "aiaocsp", false, "prefer to use AIA OCSP for signing [deprecated]");
    options.addOption("noaiaocsp", "noaiaocsp", false, "disable AIA OCSP preference for signing");
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
    options.addOption(DigiDoc4J.tspSource());
    options.addOption(DigiDoc4J.tspSourceArchive());
    options.addOption(DigiDoc4J.tstDigestAlgorihm());
    options.addOption(DigiDoc4J.tstReferenceDigestAlgorihm());
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
    return Option.builder(ExecutionOption.DTS.getName())
        .argName("path")
        .hasArg()
        .desc("specifies location path of signing data file")
        .longOpt("signingDataFile")
        .build();
  }

  private static Option signatureFile() {
    return Option.builder(ExecutionOption.SIGNATURE.getName())
        .argName("path")
        .hasArg()
        .desc("specifies location path of signature file")
        .longOpt("signatureFile")
        .build();
  }

  private static Option certificateFile() {
    return Option.builder(ExecutionOption.CERTIFICATE.getName())
        .argName("path")
        .hasArg()
        .desc("specifies loaction path of public certificate file")
        .longOpt("certificateFile")
        .build();
  }

  private static Option tspSource() {
    return Option.builder(ExecutionOption.TSPSOURCE.getName())
        .argName("tspSource")
        .hasArg()
        .desc("sets TSP source URL for signature timestamps")
        .build();
  }

  private static Option tspSourceArchive() {
    return Option.builder(ExecutionOption.TSPSOURCEARCHIVE.getName())
        .argName("tspSourceArchive")
        .hasArg()
        .desc("sets TSP source URL for archive timestamps.")
        .build();
  }

  private static Option tstDigestAlgorihm() {
    return Option.builder(ExecutionOption.DATST.getName())
        .argName("digestAlgorithm")
        .hasArgs()
        .desc("sets the digest algorithm for archive timestamps. " +
            "Defaults to the value defined in configuration if unset.")
        .build();
  }

  private static Option tstReferenceDigestAlgorihm() {
    return Option.builder(ExecutionOption.REFDATST.getName())
        .argName("referenceDigestAlgorithm")
        .hasArgs()
        .desc("sets reference digest algorithm. " +
            "Used when a timestamp has to cover a collection of references (e.g. an ASiCArchiveManifest.xml file), " +
            "and each reference needs to incorporate the digest of the entity it references.")
        .build();
  }

  private static Option signatureProfile() {
    return Option.builder("p")
        .argName("signatureProfile")
        .hasArg()
        .desc("sets signature profile. Profile can be B_BES, LT or LTA")
        .longOpt("profile")
        .build();
  }

  private static Option encryptionAlgorithm() {
    return Option.builder("e")
        .argName("encryptionAlgorithm")
        .hasArg()
        .desc("sets the encryption algorithm (RSA/ECDSA).")
        .longOpt("encryption")
        .build();
  }

  private static Option pkcs12Sign() {
    return Option.builder("pkcs12")
        .argName("pkcs12Keystore password")
        .numberOfArgs(2)
        .desc("sets pkcs12 keystore and keystore password")
        .build();
  }

  private static Option pkcs11Sign() {
    return Option.builder("pkcs11")
        .argName("pkcs11ModulePath pin slot label")
        .hasArgs()
        .desc("sets pkcs11 module path, pin(password), slot index and (optionally) keypair label")
        .build();
  }

  private static Option removeFile() {
    return Option.builder("remove")
        .argName("file")
        .hasArg()
        .desc("removes file from container")
        .build();
  }

  private static Option addFile() {
    return Option.builder("add")
        .argName("file mime-type")
        .numberOfArgs(2)
        .desc("adds file specified with mime type to container")
        .build();
  }

  private static Option inputFile() {
    return Option.builder("in")
        .argName("file")
        .hasArg()
        .desc("opens or creates container")
        .build();
  }

  private static Option inputDir() {
    return Option.builder("inputDir")
        .argName("inputDir")
        .hasArg()
        .desc("directory path containing data files to sign")
        .build();
  }

  private static Option reportsDir() {
    return Option.builder("r")
        .argName("reportDir")
        .hasArg()
        .desc("directory path for validation reports")
        .longOpt("reportDir")
        .build();
  }

  private static Option mimeType() {
    return Option.builder("mimeType")
        .argName("mimeType")
        .hasArg()
        .desc("specifies input file mime type when using inputDir")
        .build();
  }

  private static Option outputDir() {
    return Option.builder("outputDir")
        .argName("outputDir")
        .hasArg()
        .desc("directory path where containers are saved")
        .build();
  }

  private static Option type() {
    return Option.builder("t")
        .argName("type")
        .hasArg()
        .desc("sets container type. Types can be BDOC, ASICE or ASICS")
        .longOpt("type")
        .build();
  }

  private static Option extractDataFile() {
    return Option.builder(ExecutionOption.EXTRACT.getName())
        .argName("fileName destination")
        .numberOfArgs(2)
        .desc("extracts the file from the container to the specified destination")
        .build();
  }

  private static Option detachedXades() {
    return Option.builder(ExecutionOption.DETACHED_XADES.getName())
        .hasArg(false)
        .desc("operates with detached XadES")
        .build();
  }

  private static Option addDigestFile() {
    return Option.builder(ExecutionOption.DIGEST_FILE.getName())
        .argName("name digest mimeType")
        .numberOfArgs(ExecutionOption.DIGEST_FILE.getCount())
        .desc("sets digest (in base64) data file for detached XadES")
        .build();
  }

  private static Option xadesOutputPath() {
    return Option.builder(ExecutionOption.XADES_OUTPUT_PATH.getName())
        .argName("path")
        .hasArg()
        .desc("sets the destination where detached XadES signature will be saved")
        .build();
  }

  private static Option xadesInputPath() {
    return Option.builder(ExecutionOption.XADES_INPUT_PATH.getName())
        .argName("path")
        .hasArg()
        .desc("sets the source where detached XadES signature will read from")
        .build();
  }

  private static void showVersion() {
    System.out.println("DigiDoc4j version " + Version.VERSION);
  }

}
