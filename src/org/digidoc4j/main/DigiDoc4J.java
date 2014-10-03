package org.digidoc4j.main;

import org.apache.commons.cli.*;
import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.digidoc4j.Signer;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.impl.ValidationResultForDDoc;
import org.digidoc4j.signers.PKCS12Signer;

import java.io.File;
import java.util.List;

import static org.apache.commons.cli.OptionBuilder.withArgName;
import static org.digidoc4j.Container.DocumentType;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;

/**
 * Client commandline tool for DigiDoc4J library.
 */
public final class DigiDoc4J {

  private static boolean verboseMode;
  private static final String ANSI_RED = "\033[31m";
  private static final String ANSI_RESET = "\033[0m";

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
      System.err.print(e.getMessage());
      System.exit(e.getErrorCode());
    }
    System.exit(0);
  }

  private static void run(String[] args) {
    Options options = createParameters();

    CommandLine commandLine = null;

    try {
      commandLine = new BasicParser().parse(options, args);
    } catch (ParseException e) {
      showUsage(options);
    }

    execute(commandLine);
  }

  private static void showUsage(Options options) {
    new HelpFormatter().printHelp("digidoc4j", options);
    throw new DigiDoc4JUtilityException(2, "no parameters given");
  }

  private static void execute(CommandLine commandLine) {
    boolean fileHasChanged = false;

    verboseMode = commandLine.hasOption("verbose");
    String inputFile = commandLine.getOptionValue("in");
    DocumentType type = getContainerType(commandLine);

    checkSupportedFunctionality(commandLine);

    try {
      Container container;

      if (new File(inputFile).exists() || commandLine.hasOption("verify") || commandLine.hasOption("remove")) {
        verboseMessage("Opening container " + inputFile);
        container = Container.open(inputFile);
      } else {
        verboseMessage("Creating new " + type + "container " + inputFile);
        container = Container.create(type);
      }

      if (commandLine.hasOption("add")) {
        String[] optionValues = commandLine.getOptionValues("add");
        container.addDataFile(optionValues[0], optionValues[1]);
        fileHasChanged = true;
      }

      if (commandLine.hasOption("remove")) {
        container.removeDataFile(commandLine.getOptionValue("remove"));
        fileHasChanged = true;
      }

      if (commandLine.hasOption("pkcs12")) {
        pkcs12Sign(commandLine, container);
        fileHasChanged = true;
      }

      if (fileHasChanged)
        container.save(inputFile);

      if (commandLine.hasOption("verify"))
        verify(container);
    } catch (DigiDoc4JException e) {
      System.out.println("Fatal error: " + e.toString());
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
  }

  private static DocumentType getContainerType(CommandLine commandLine) {
    if ("BDOC".equals(commandLine.getOptionValue("type"))) return BDOC;
    if ("DDOC".equals(commandLine.getOptionValue("type"))) return DDOC;

    String fileName = commandLine.getOptionValue("in");
    if (fileName != null) {
      if (fileName.toLowerCase().endsWith(".bdoc")) return BDOC;
      if (fileName.toLowerCase().endsWith(".ddoc")) return DDOC;
    }
    return BDOC;
  }

  private static void pkcs12Sign(CommandLine commandLine, Container container) {
    String[] optionValues = commandLine.getOptionValues("pkcs12");
    Signer pkcs12Signer = new PKCS12Signer(optionValues[0], optionValues[1].toCharArray());
    container.sign(pkcs12Signer);
  }

  static void verify(Container container) {
    ValidationResult validationResult = container.validate();

    boolean isDDoc = container.getDocumentType() == DocumentType.DDOC;
    if (isDDoc) {
      List<DigiDoc4JException> exceptions = ((ValidationResultForDDoc) validationResult).getContainerErrors();
      for (DigiDoc4JException exception : exceptions) {
        System.out.println("\t" + exception.toString());
      }
      if (((ValidationResultForDDoc) validationResult).hasFatalErrors()) {
        return;
      }
    }

    List<Signature> signatures = container.getSignatures();
    if (signatures == null) {
      throw new SignatureNotFoundException();
    }

    for (Signature signature : signatures) {
      List<DigiDoc4JException> signatureValidationResult = signature.validate();
      if (signatureValidationResult.size() == 0) {
        System.out.println("Signature " + signature.getId() + " is valid");
      } else {
        System.out.println(ANSI_RED + "Signature " + signature.getId() + " is not valid" + ANSI_RESET);
        for (DigiDoc4JException exception : signatureValidationResult) {
          System.out.println("\t" + exception.toString());
        }
      }
    }
  }

  private static Options createParameters() {
    Options options = new Options();
    options.addOption("v", "verify", false, "verify input file");
    options.addOption("verbose", "verbose", false, "verbose output");

    options.addOption(type());
    options.addOption(inputFile());
    options.addOption(addFile());
    options.addOption(removeFile());
    options.addOption(pkcs12Sign());

    return options;
  }

  private static void verboseMessage(String message) {
    if (verboseMode)
      System.out.println(message);
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option pkcs12Sign() {
    return withArgName("pkcs12Keystore password").hasArgs(2).withValueSeparator(' ')
        .withDescription("sets pkcs12 keystore and keystore password").create("pkcs12");
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
    Option inputFile = withArgName("file").hasArg()
        .withDescription("opens or creates container").create("in");
    inputFile.setRequired(true);
    return inputFile;
  }

  @SuppressWarnings("AccessStaticViaInstance")
  private static Option type() {
    Option type = withArgName("type").hasArg()
        .withDescription("sets container type. types can be DDOC or BDOC").create("t");
    type.setLongOpt("type");
    return type;
  }
}

