package org.digidoc4j.main;

import java.io.File;
import java.util.List;

import org.apache.commons.cli.*;
import org.digidoc4j.api.Container;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.Signer;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.PKCS12Signer;

import static org.digidoc4j.ContainerInterface.DocumentType.DDOC;

/**
 * Client commandline tool for DigiDoc4J library.
 */
public final class DigiDoc4J {

  private DigiDoc4J() {

  }

  /**
   * @param args args for main method. No arguments are actually used
   * @throws Exception throws exception if the command cannot be executed successfully
   */
  public static void main(String[] args) {
    Options options = createParameters();

    CommandLine commandLine = null;

    try {
      commandLine = new BasicParser().parse(options, args);
    }
    catch (ParseException e) {
      new HelpFormatter().printHelp("digido4j", options);
      System.exit(1);
    }

    run(commandLine);

    System.exit(0);
  }

  private static void run(CommandLine commandLine) {
    boolean fileHasChanged = false;
    String inputFile = commandLine.getOptionValue("in");
    Container container = new Container(DDOC);

    if (new File(inputFile).exists())
      container = new Container(inputFile);

    if (commandLine.hasOption("add")) {
      container.addDataFile(commandLine.getOptionValue("add"), "text/plain");
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
    options.addOption("v", "verify", false, "verify command");

    Option inputFile = OptionBuilder.withArgName("file").hasArg().withDescription("opens or creates container").create("in");
    inputFile.setRequired(true);

    options.addOption(inputFile);
    options.addOption(OptionBuilder.withArgName("file").hasArg().withDescription("adds file to container").create("add"));
    options.addOption(OptionBuilder.withArgName("pkcs12Keystore password").hasArgs(2).withValueSeparator(' ')
                        .withDescription("sets pkcs12 keystore and keystore password").create("pkcs12"));
    options.addOption(OptionBuilder.withArgName("slot pin").hasArgs(2).withValueSeparator(' ')
                        .withDescription("sets pkcs11 singner slot and pin").create("pkcs11"));

    return options;
  }
}

