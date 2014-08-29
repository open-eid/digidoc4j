package org.digidoc4j.main;

import org.apache.commons.cli.*;
import org.digidoc4j.api.Container;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.Signer;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12Signer;

import java.io.File;
import java.util.List;

import static org.apache.commons.cli.OptionBuilder.withArgName;
import static org.digidoc4j.api.Container.DocumentType;
import static org.digidoc4j.api.Container.DocumentType.BDOC;
import static org.digidoc4j.api.Container.DocumentType.DDOC;

/**
 * Client commandline tool for DigiDoc4J library.
 */
public final class DigiDoc4J {

  private DigiDoc4J() {
  }

  /**
   * Utility main method
   *
   * @param args command line arguments
   */
  public static void main(String[] args) {
    try {
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

    String inputFile = commandLine.getOptionValue("in");
    DocumentType type = getContainerType(commandLine);

    checkSupportedFunctionality(commandLine);

    try {
      Container container = Container.create(type);

      if (new File(inputFile).exists() || commandLine.hasOption("verify") || commandLine.hasOption("remove"))
        container = Container.open(inputFile);

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
      throw new DigiDoc4JUtilityException(1, e.getMessage());
    }
  }

  private static void checkSupportedFunctionality(CommandLine commandLine) {
    if (getContainerType(commandLine) == BDOC) {
      throw new DigiDoc4JUtilityException(2, "BDOC format is not supported yet");
    }
    if (commandLine.hasOption("add")) {
      String[] optionValues = commandLine.getOptionValues("add");
      if (optionValues.length != 2) {
        throw new DigiDoc4JUtilityException(2, "Incorrect add command");
      }
    }
  }

  private static DocumentType getContainerType(CommandLine commandLine) {
    if ("BDOC".equals(commandLine.getOptionValue("type")))
      return BDOC;
    return DDOC;
  }

  private static void pkcs12Sign(CommandLine commandLine, Container container) {
    String[] optionValues = commandLine.getOptionValues("pkcs12");
    Signer pkcs12Signer = new PKCS12Signer(optionValues[0], optionValues[1]);
    container.sign(pkcs12Signer);
  }

  private static void verify(Container container) {
    List<Signature> signatures = container.getSignatures();
    if (signatures == null) {
      throw new DigiDoc4JException("No signatures found");
    }
    for (Signature signature : signatures) {
      List<DigiDoc4JException> validationResult = signature.validate();
      if (validationResult.size() == 0) {
        System.out.println("Signature " + signature.getId() + " is valid");
      } else {
        System.out.println("Signature " + signature.getId() + " is not valid");
        for (DigiDoc4JException exception : validationResult) {
          System.out.println(exception.getMessage());
        }
      }
    }
  }

  private static Options createParameters() {
    Options options = new Options();
    options.addOption("v", "verify", false, "verify input file");

    options.addOption(type());
    options.addOption(inputFile());
    options.addOption(addFile());
    options.addOption(removeFile());
    options.addOption(pkcs12Sign());

    return options;
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

