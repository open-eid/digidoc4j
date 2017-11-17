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

import static org.apache.commons.cli.OptionBuilder.withArgName;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.digidoc4j.Container;
import org.digidoc4j.Version;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

/**
 * Client commandline tool for DigiDoc4J library.
 */
public final class DigiDoc4J {

  private static final Logger logger = LoggerFactory.getLogger(DigiDoc4J.class);
  private static final String EXTRACT_CMD = "extract";

  private DigiDoc4J() {
  }

  /**
   * Utility main method
   *
   * @param args command line arguments
   */
  public static void main(String[] args) {
    try {
      if (System.getProperty("digidoc4j.mode") == null)
        System.setProperty("digidoc4j.mode", "PROD");
      run(args);
    } catch (DigiDoc4JUtilityException e) {
      logger.error("Errors occurred when running utility method: " + e.getMessage());
      System.err.print(e.getMessage());
      System.exit(e.getErrorCode());
    }
    logger.info("Finished running utility method");
    System.exit(0);
  }

  private static void run(String[] args) {
    Options options = createParameters();

    try {
      CommandLine commandLine = new BasicParser().parse(options, args);
      if (commandLine.hasOption("version")) {
        showVersion();
      }
      if (shouldManipulateContainer(commandLine)) {
        execute(commandLine);
      }
      if (!commandLine.hasOption("version") && !shouldManipulateContainer(commandLine)) {
        showUsage(options);
      }
    } catch (ParseException e) {
      logger.error(e.getMessage());
      showUsage(options);
    }
  }

  private static void showUsage(Options options) {
    new HelpFormatter().printHelp("digidoc4j/" + Version.VERSION, options);
    throw new DigiDoc4JUtilityException(2, "wrong parameters given");
  }

  private static boolean shouldManipulateContainer(CommandLine commandLine) {
    return commandLine.hasOption("in") || (isMultipleContainerCreation(commandLine));
  }

  private static void execute(CommandLine commandLine) {
    checkSupportedFunctionality(commandLine);
    ContainerManipulator containerManipulator = new ContainerManipulator(commandLine);
    try {
      if (commandLine.hasOption("in")) {
        String containerPath = commandLine.getOptionValue("in");
        Container container = containerManipulator.openContainer(containerPath);
        containerManipulator.processContainer(container);
        containerManipulator.saveContainer(container, containerPath);
      } else if (isMultipleContainerCreation(commandLine)) {
        MultipleContainersCreator containersCreator = new MultipleContainersCreator(commandLine);
        containersCreator.signDocuments();
      }
    } catch (DigiDoc4JUtilityException e) {
      throw e;
    } catch (DigiDoc4JException e) {
      throw new DigiDoc4JUtilityException(1, e.getMessage());
    }
  }

  private static void checkSupportedFunctionality(CommandLine commandLine) {
    if (commandLine.hasOption("add")) {
      String[] optionValues = commandLine.getOptionValues("add");
      if (optionValues.length != 2) {
        throw new DigiDoc4JUtilityException(2, "Incorrect add command");
      }
    }
    if (commandLine.hasOption(EXTRACT_CMD)) {
      String[] optionValues = commandLine.getOptionValues(EXTRACT_CMD);
      if (optionValues.length != 2) {
        throw new DigiDoc4JUtilityException(3, "Incorrect extract command");
      }
    }
    if (commandLine.hasOption("pkcs11") && commandLine.hasOption("pkcs12")) {
      throw new DigiDoc4JUtilityException(5, "Cannot sign with both PKCS#11 and PKCS#12");
    }
  }

  private static boolean isMultipleContainerCreation(CommandLine commandLine) {
    return commandLine.hasOption("inputDir") && commandLine.hasOption("outputDir");
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

  private static Options createParameters() {
    Options options = new Options();
    options.addOption("v", "verify", false, "verify input file");
    options.addOption("v2", "verify2", false, "verify_and_report input file");
    options.addOption("verbose", "verbose", false, "verbose output");
    options.addOption("w", "warnings", false, "show warnings");
    options.addOption("version", "version", false, "show version");

    options.addOption(type());
    options.addOption(inputFile());
    options.addOption(inputDir());
    options.addOption(outputDir());
    options.addOption(addFile());
    options.addOption(removeFile());
    options.addOption(pkcs12Sign());
    options.addOption(pkcs11Sign());
    options.addOption(signatureProfile());
    options.addOption(encryptionAlgorithm());
    options.addOption(mimeType());
    options.addOption(extractDataFile());
    options.addOption(reportsDir());

    return options;
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option signatureProfile() {
    return withArgName("signatureProfile").hasArg()
        .withDescription("sets signature profile. Profile can be B_BES, LT, LT_TM or LTA")
        .withLongOpt("profile").create("p");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option encryptionAlgorithm() {
    return withArgName("encryptionAlgorithm").hasArg()
        .withDescription("sets the encryption algorithm (RSA/ECDSA).").withLongOpt("encryption").create("e");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option pkcs12Sign() {
    return withArgName("pkcs12Keystore password").hasArgs(2).withValueSeparator(' ')
        .withDescription("sets pkcs12 keystore and keystore password").create("pkcs12");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option pkcs11Sign() {
    return withArgName("pkcs11ModulePath pin slot").hasArgs(3).withValueSeparator(' ')
        .withDescription("sets pkcs11 module path, pin(password) and a slot index").create("pkcs11");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option removeFile() {
    return withArgName("file").hasArg()
        .withDescription("removes file from container").create("remove");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option addFile() {
    return withArgName("file mime-type").hasArgs(2)
        .withDescription("adds file specified with mime type to container").create("add");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option inputFile() {
    return withArgName("file").hasArg()
        .withDescription("opens or creates container").create("in");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option inputDir() {
    return withArgName("inputDir").hasArg()
        .withDescription("directory path containing data files to sign").create("inputDir");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option reportsDir() {
    return withArgName("reportDir").hasArg()
        .withDescription("directory path for validation reports")
        .withLongOpt("reportDir").create("r");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option mimeType() {
    return withArgName("mimeType").hasArg()
        .withDescription("Specifies input file mime type when using inputDir").create("mimeType");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option outputDir() {
    return withArgName("outputDir").hasArg()
        .withDescription("directory path where containers are saved").create("outputDir");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option type() {
    return withArgName("type").hasArg()
        .withDescription("sets container type. types can be DDOC or BDOC or ASICS").withLongOpt("type").create("t");
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option extractDataFile() {
    return withArgName("fileName destination").hasArgs(2)
        .withDescription("extracts the file from the container to the specified destination").create(EXTRACT_CMD);
  }

  private static void showVersion() {
    System.out.println("DigiDoc4j version " + Version.VERSION);
  }
}
