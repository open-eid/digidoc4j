package org.digidoc4j.main;

import java.io.File;
import java.util.List;

import org.apache.commons.cli.*;
import org.digidoc4j.api.Container;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.Signer;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.PKCS12Signer;

import static org.digidoc4j.ContainerInterface.DocumentType;
import static org.digidoc4j.ContainerInterface.DocumentType.ASIC;
import static org.digidoc4j.ContainerInterface.DocumentType.DDOC;

/**
 * Client commandline tool for DigiDoc4J library.
 */
public final class DigiDoc4J {

  public static void main(String[] args) {
    Options options = createParameters();

    CommandLine commandLine = null;

    try {
      commandLine = new BasicParser().parse(options, args);
    }
    catch (ParseException e) {
      showUsageAndExit(options);
    }

    run(commandLine);

    System.exit(0);
  }

  private static void showUsageAndExit(Options options) {
    new HelpFormatter().printHelp("digido4j", options);
    System.exit(2);
  }

  private static void run(CommandLine commandLine) {
    boolean fileHasChanged = false;

    String inputFile = commandLine.getOptionValue("in");
    DocumentType type = getContainerType(commandLine);

    checkSupportedFunctionality(commandLine);

    try {
      Container container = new Container(type);

      if (new File(inputFile).exists())
        container = new Container(inputFile);

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
    }
    catch (DigiDoc4JException e) {
      System.out.println(e.getMessage());
      System.exit(1);
    }
  }

  private static void checkSupportedFunctionality(CommandLine commandLine) {
    if (getContainerType(commandLine) == DocumentType.ASIC) {
      System.out.println("BDOC format is not supported yet");
      System.exit(2);
    }

    if (commandLine.hasOption("add")) {
      String[] optionValues = commandLine.getOptionValues("add");
      if (optionValues.length != 2) {
        System.out.println("Incorrect add command");
        System.exit(2);
      }
    }
  }

  private static DocumentType getContainerType(CommandLine commandLine) {
    if ("BDOC".equals(commandLine.getOptionValue("type")))
      return ASIC;
    return DDOC;
  }

  private static void pkcs12Sign(CommandLine commandLine, Container container) {
    String[] optionValues = commandLine.getOptionValues("pkcs12");
    Signer pkcs12Signer = new PKCS12Signer(optionValues[0], optionValues[1]);
    container.sign(pkcs12Signer);
  }

  private static void verify(Container container) {
    List<Signature> signatures = container.getSignatures();
    for (Signature signature : signatures) {
      List<DigiDoc4JException> validationResult = signature.validate();
      if (validationResult.size() == 0) {
        System.out.println("Signature " + signature.getId() + " is valid");
      }
      else {
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

  private static Option pkcs12Sign() {
    return OptionBuilder.withArgName("pkcs12Keystore password").hasArgs(2).withValueSeparator(' ')
      .withDescription("sets pkcs12 keystore and keystore password").create("pkcs12");
  }

  private static Option removeFile() {
    return OptionBuilder.withArgName("file").hasArg()
      .withDescription("removes file from container").create("remove");
  }

  private static Option addFile() {
    Option option = OptionBuilder.withArgName("file mime-type").hasArgs(2)
      .withDescription("adds file specified with mime type to container").create("add");
    return option;
  }

  private static Option inputFile() {
    Option inputFile = OptionBuilder.withArgName("file").hasArg()
      .withDescription("opens or creates container").create("in");
    inputFile.setRequired(true);
    return inputFile;
  }

  private static Option type() {
    Option type = OptionBuilder.withArgName("type").hasArg()
      .withDescription("sets container type. types can be DDOC or BDOC").create("t");
    type.setLongOpt("type");
    return type;
  }
}

