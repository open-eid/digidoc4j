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

import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS11SignatureToken;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.digidoc4j.Container.DocumentType.PADES;

/**
 * Class for executing digidoc4j-util commands.
 */
public class CommandLineExecutor {

  private static final Logger LOGGER = LoggerFactory.getLogger(CommandLineExecutor.class);
  private final ExecutionContext context;
  private boolean fileHasChanged;

  /**
   * @param context execution context
   */
  public CommandLineExecutor(ExecutionContext context) {
    this.context = context;
  }

  /**
   * @param container container
   */
  public void processContainer(Container container) {
    LOGGER.debug("Processing container");

    overrideConfiguration(container);

    switch (getContainerType()) {
      case PADES:
        verifyPadesContainer(container);
        return;
      case DDOC:
        processDataFileCommands(container);
        break;
      case ASICS:
        checkInputArgsForAsicSContainer();
        processDataFileCommands(container);
        processAsicSContainerSpecificCommands(container);
        break;
      default:
        processDataFileCommands(container);
        signContainer(container);
    }
    verifyContainer(container);
  }

  private void checkInputArgsForAsicSContainer() {
    // This check should be here for as long as adding signature to ASiCS container is not supported.
    // See org.digidoc4j.impl.asic.asics.AsicSContainer::addSignature
    if (hasAnyOption(ExecutionOption.PKCS11.getName(), ExecutionOption.PKCS12.getName())) {
      throw new DigiDoc4JException("Signing of ASiCS container is not supported.");
    }
  }

  private void processAsicSContainerSpecificCommands(Container container) {
    if (hasAnyOption(ExecutionOption.TST.getName())) {
      signContainerWithTst(container);
    } else if (hasAnyOption(ExecutionOption.PKCS11.getName(), ExecutionOption.PKCS12.getName())) {
      verifyIfAllowedToAddSignatureForAsics(container);
      signContainer(container);
    } else {
      LOGGER.debug("Signing or timestamping was not requested for this ASiC-S container.");
    }
  }

  /**
   * @return indication whether this executor has internal command found
   */
  public boolean hasCommand() {
    return context.getCommand() != null;
  }

  /**
   * Executes internal command
   */
  public void executeCommand() {
    if (hasCommand()) {
      for (ExecutionOption option : context.getCommand().getMandatoryOptions()) {
        switch (option) {
          case IN:
            context.setContainer(openContainer(context.getCommandLine().getOptionValue(option.getName())));
            break;
          case ADD:
            try {
              context.getContainer();
            } catch (DigiDoc4JException ignored) {
              context.setContainer(openContainer());
            }
            addData(context.getContainer());
            break;
          case CERTIFICATE:
            context.setCertificate(loadCertificate());
            break;
          case DTS:
            switch (context.getCommand()) {
              case EXTERNAL_COMPOSE_DTS:
                context.setDataToSign(createSigningData());
                break;
              case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS11:
              case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS12:
                context.setDataToSign(loadSigningData());
                break;
              case EXTERNAL_ADD_SIGNATURE:
                context.setDataToSign(loadSigningData());
                break;
            }
            break;
          case PKCS11:
            context.setSignatureToken(loadPKCS11Token());
            break;
          case PKCS12:
            context.setSignatureToken(loadPKCS12Token());
            break;
          case SIGNATURE:
            switch (context.getCommand()) {
              case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS11:
              case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS12:
                context.setSignature(createSignature());
                break;
              case EXTERNAL_ADD_SIGNATURE:
                context.setSignature(loadSignature());
            }
            break;
          default:
            LOGGER.warn("No option <{}> implemented", option);
        }
      }
      postExecutionProcess();
    } else {
      throw new DigiDoc4JException("No command to execute");
    }
  }

  /**
   * Gets container type for util logic
   *
   * @return document type of container
   */
  public Container.DocumentType getContainerType() {
    String type = context.getCommandLine().getOptionValue(ExecutionOption.TYPE.getName());

    if (StringUtils.equalsAnyIgnoreCase(type, BDOC.name(), ASICS.name(), ASICE.name(), DDOC.name())) {
      return Container.DocumentType.valueOf(type);
    }

    String in = context.getCommandLine().getOptionValue(ExecutionOption.IN.getName());

    if (StringUtils.endsWithIgnoreCase(in, ".bdoc")) {
      return BDOC;
    } else if (StringUtils.endsWithIgnoreCase(in, ".asics") || StringUtils.endsWithIgnoreCase(in, ".scs")) {
      return ASICS;
    } else if (StringUtils.endsWithIgnoreCase(in, ".asice") || StringUtils.endsWithIgnoreCase(in, ".sce")) {
      return ASICE;
    } else if (StringUtils.endsWithIgnoreCase(in, ".ddoc")) {
      return DDOC;
    } else if (StringUtils.endsWithIgnoreCase(in, ".pdf")) {
      return PADES;
    }

    LOGGER.warn("Unable to detect container type for provided arguments, defaulting to ASICE");
    return ASICE;
  }

  /**
   * @return generated container
   */
  public Container openContainer() {
    return openContainer("");
  }

  /**
   * @param containerPath path
   * @return existing or generated container
   */
  public Container openContainer(String containerPath) {
    Container.DocumentType type = getContainerType();
    if (new File(containerPath).exists() ||
        context.getCommandLine().hasOption(ExecutionOption.VERIFY.getName()) ||
        context.getCommandLine().hasOption(ExecutionOption.REMOVE.getName())) {
      LOGGER.debug("Opening container " + containerPath);
      return ContainerOpener.open(containerPath);
    } else {
      LOGGER.debug("Creating new " + type + "container " + containerPath);
      return ContainerBuilder.aContainer(type.name()).build();
    }
  }

  /**
   * Stores container to given path
   *
   * @param container container
   * @param containerPath path
   */
  public void saveContainer(Container container, String containerPath) {
    if (fileHasChanged) {
      container.saveAsFile(containerPath);
      if (new File(containerPath).exists()) {
        LOGGER.debug("Container has been successfully saved to " + containerPath);
      } else {
        LOGGER.warn("Container was NOT saved to " + containerPath);
      }
    } else {
      LOGGER.warn("Container was NOT saved because there were no changes.");
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private void verifyIfAllowedToAddSignatureForAsics(Container container) {
    if (CollectionUtils.isNotEmpty(container.getTimestamps())) {
      throw new DigiDoc4JException("This container has already timestamp. Should be no signatures in case of timestamped ASiCS container.");
    }
    if (CollectionUtils.isNotEmpty(container.getSignatures())) {
      throw new DigiDoc4JException("This container is already signed. Should be only one signature in case of ASiCS container.");
    }
  }

  private void processDataFileCommands(Container container) {
    addDataFile(container);
    removeDataFile(container);
    extractDataFile(container);
  }

  private void addDataFile(Container container) {
    if (context.getCommandLine().hasOption(ExecutionOption.ADD.getName())) {
      addData(container);
    }
  }

  private void removeDataFile(Container container) {
    if (context.getCommandLine().hasOption(ExecutionOption.REMOVE.getName())) {
      LOGGER.debug("Removing data file");
      String fileToRemove = context.getCommandLine().getOptionValue(ExecutionOption.REMOVE.getName());
      container.removeDataFile(container.getDataFiles().stream()
          .filter(dataFile -> fileToRemove.equals(dataFile.getName()))
          .findFirst().orElseThrow(() -> new DataFileNotFoundException("No datafile found: " + fileToRemove))
      );
      fileHasChanged = true;
    }
  }

  private void extractDataFile(Container container) {
    if (context.getCommandLine().hasOption(ExecutionOption.EXTRACT.getName())) {
      LOGGER.debug("Extracting data file");

      String[] optionValues = context.getCommandLine().getOptionValues(ExecutionOption.EXTRACT.getName());
      String fileNameToExtract = optionValues[0];
      String extractPath = optionValues[1];
      boolean fileFound = false;
      for (DataFile dataFile : container.getDataFiles()) {
        if (StringUtils.equalsIgnoreCase(fileNameToExtract, dataFile.getName())) {
          LOGGER.info("Extracting " + dataFile.getName() + " to " + extractPath);
          dataFile.saveAs(extractPath);
          fileFound = true;
        }
      }
      if (!fileFound) {
        throw new DigiDoc4JUtilityException(4, "Data file " + fileNameToExtract + " was not found in the container");
      }
    }
  }

  private void addData(Container container) {
    LOGGER.debug("Adding data to container ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.ADD.getName());
    container.addDataFile(values[0], values[1]);
    fileHasChanged = true;
  }

  private DataToSign createSigningData() {
    LOGGER.debug("Creating signing data ...");
    return SignatureBuilder.aSignature(context.getContainer()).withSigningCertificate(context.getCertificate())
        .withSignatureDigestAlgorithm(context.getDigestAlgorithm()).buildDataToSign();
  }

  private byte[] createSignature() {
    LOGGER.debug("Creating signature ...");
    return context.getSignatureToken().sign(context.getDigestAlgorithm(), context.getDataToSign().getDataToSign());
  }

  private X509Certificate loadCertificate() {
    LOGGER.debug("Loading certificate ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.CERTIFICATE.getName());
    try (InputStream stream = new FileInputStream(values[0])) {
      return DSSUtils.loadCertificate(stream).getCertificate();
    } catch (IOException e) {
      throw new DigiDoc4JException(String.format("Unable to load certificate file from <%s>", values[0]), e);
    }
  }

  private DataToSign loadSigningData() {
    LOGGER.debug("Loading signing data ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.DTS.getName());
    try {
      return Helper.deserializer(values[0]);
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to load signing data file from <%s>", values[0]), e);
    }
  }

  private byte[] loadSignature() {
    LOGGER.debug("Loading signature ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.SIGNATURE.getName());
    try {
      return Files.readAllBytes(Paths.get(values[0]));
    } catch (IOException e) {
      throw new DigiDoc4JException(String.format("Unable to load signature file from <%s>", values[0]), e);
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
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.PKCS12.getName());
    try {
      return new PKCS12SignatureToken(values[0], values[1].toCharArray());
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to load PKCS12 token <%s, %s>", values[0], values[1]));
    }
  }

  private void storeSignature() {
    LOGGER.debug("Storing signature ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.SIGNATURE.getName());
    try (OutputStream stream = new FileOutputStream(values[0])) {
      IOUtils.write(context.getSignature(), stream);
    } catch (IOException e) {
      throw new DigiDoc4JException(String.format("Unable to store signature file to <%s>", values[0]), e);
    }
  }

  private void storeSigningData() {
    LOGGER.debug("Storing signing data ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.DTS.getName());
    try {
      Helper.serialize(context.getDataToSign(), values[0]);
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to store signing data file to <%s>", values[0]), e);
    }
  }

  private void storeContainer() {
    LOGGER.debug("Storing container ...");
    String[] values = context.getCommandLine().getOptionValues(ExecutionOption.IN.getName());
    try {
      context.getContainer().saveAsFile(values[0]);
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to store container file to <%s>", values[0]), e);
    }
  }

  private void storeContainerWithSignature() {
    LOGGER.debug("Adding signature to container ...");
    Container container = context.getContainer();
    container.addSignature(context.getDataToSign().finalize(context.getSignature()));
    fileHasChanged = true;
    saveContainer(container, context.getCommandLine().getOptionValue(ExecutionOption.IN.getName()));
  }

  private void postExecutionProcess() {
    switch (context.getCommand()) {
      case EXTERNAL_COMPOSE_DTS:
        storeSigningData();
        storeContainer();
        break;
      case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS11:
      case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS12:
        storeSignature();
        break;
      case EXTERNAL_ADD_SIGNATURE:
        storeContainerWithSignature();
        break;
    }
  }

  private void signContainer(Container container) {
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);
    updateProfile(signatureBuilder);
    updateEncryptionAlgorithm(signatureBuilder);
    useAiaOcsp(container);
    signWithPkcs12(container, signatureBuilder);
    signWithPkcs11(container, signatureBuilder);
  }

  private void updateProfile(SignatureBuilder signatureBuilder) {
    if (context.getCommandLine().hasOption(ExecutionOption.PROFILE.getName())) {
      String profile = context.getCommandLine().getOptionValue(ExecutionOption.PROFILE.getName());
      try {
        SignatureProfile signatureProfile = SignatureProfile.valueOf(profile);
        signatureBuilder.withSignatureProfile(signatureProfile);
      } catch (IllegalArgumentException e) {
        System.out.println("Signature profile \"" + profile + "\" is unknown and will be ignored");
      }
    }
  }

  private void updateEncryptionAlgorithm(SignatureBuilder signatureBuilder) {
    if (context.getCommandLine().hasOption(ExecutionOption.ENCRYPTION.getName())) {
      String encryption = context.getCommandLine().getOptionValue(ExecutionOption.ENCRYPTION.getName());
      EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.valueOf(encryption);
      signatureBuilder.withEncryptionAlgorithm(encryptionAlgorithm);
    }
  }

  private void useAiaOcsp(Container container) {
    if (context.getCommandLine().hasOption(ExecutionOption.NOAIAOCSP.getName())) {
      Configuration configuration = container.getConfiguration();
      configuration.setPreferAiaOcsp(false);
    } else if (context.getCommandLine().hasOption(ExecutionOption.AIAOCSP.getName())) {
      LOGGER.warn("Option 'aiaocsp' is deprecated; preference to use AIA OCSP is enabled by default");
    }
  }

  private void signWithPkcs12(Container container, SignatureBuilder signatureBuilder) {
    if (context.getCommandLine().hasOption(ExecutionOption.PKCS12.getName())) {
      String[] optionValues = context.getCommandLine().getOptionValues(ExecutionOption.PKCS12.getName());
      SignatureToken pkcs12Signer = new PKCS12SignatureToken(optionValues[0], optionValues[1].toCharArray());
      Signature signature = invokeSigning(signatureBuilder, pkcs12Signer);
      container.addSignature(signature);
      fileHasChanged = true;
    }
  }

  private void signContainerWithTst(Container container) {
    if (context.getCommandLine().hasOption(ExecutionOption.PKCS12.getName()) || context.getCommandLine().hasOption(ExecutionOption.PKCS11.getName())) {
      throw new DigiDoc4JException("Timestamping and signing is not allowed.");
    }

    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container);

    LOGGER.info(
        "Following properties will be used for timestamping: TSP Source {}; timestamp digest algorithm {}, reference digest algorithm {}",
        timestampBuilder.getTspSource(),
        timestampBuilder.getTimestampDigestAlgorithm().name(),
        timestampBuilder.getReferenceDigestAlgorithm().name()
    );

    container.addTimestamp(timestampBuilder.invokeTimestamping());

    fileHasChanged = true;
  }

  private void signWithPkcs11(Container container, SignatureBuilder signatureBuilder) {
    if (context.getCommandLine().hasOption(ExecutionOption.PKCS11.getName())) {
      String[] optionValues = context.getCommandLine().getOptionValues(ExecutionOption.PKCS11.getName());
      String pkcs11ModulePath = optionValues[0];
      char[] pin = optionValues[1].toCharArray();
      int slotIndex = Integer.parseInt(optionValues[2]);
      SignatureToken pkcs11Signer;
      if (optionValues.length > 3) {
        String label = optionValues[3];
        pkcs11Signer = new PKCS11SignatureToken(pkcs11ModulePath, pin, slotIndex, label);
      } else {
        pkcs11Signer = new PKCS11SignatureToken(pkcs11ModulePath, pin, slotIndex);
      }
      Signature signature = invokeSigning(signatureBuilder, pkcs11Signer);
      container.addSignature(signature);
      fileHasChanged = true;
    }
  }

  private Signature invokeSigning(SignatureBuilder signatureBuilder, SignatureToken signatureToken) {
    return signatureBuilder.withSignatureToken(signatureToken).invokeSigning();
  }

  private void verifyContainer(Container container) {
    Path reports = null;
    if (context.getCommandLine().hasOption(ExecutionOption.REPORTDIR.getName())) {
      reports = Paths.get(context.getCommandLine().getOptionValue(ExecutionOption.REPORTDIR.getName()));
    }
    if (context.getCommandLine().hasOption(ExecutionOption.VERIFY.getName())) {
      ContainerVerifier verifier = new ContainerVerifier(context.getCommandLine());
      if (context.getCommandLine().hasOption(ExecutionOption.SHOWERRORS.getName())){
        LOGGER.warn("Option 'err/showerrors' is deprecated; in some cases, it can produce false negative validation results");
        Configuration configuration = container.getConfiguration();
        configuration.setFullReportNeeded(true);
        verifier.verify(container, reports);
      } else{
        verifier.verify(container, reports);
      }
    }
  }

  private void verifyPadesContainer(Container container) {
    SignatureValidationResult validate = container.validate();
    if (!validate.isValid()) {
      String report = validate.getReport();
      throw new DigiDoc4JException("Pades container has errors" + report);
    } else {
      LOGGER.info("Container is valid:" + validate.isValid());
    }
  }

  private void overrideConfiguration(Container container) {
    Configuration configuration = container.getConfiguration();

    getExecOptionValue(ExecutionOption.TSPSOURCE)
        .ifPresent(value -> {
          LOGGER.info("Overriding configuration value: setting TSP source: {}", value);
          configuration.setTspSource(value);
        });
    getExecOptionValue(ExecutionOption.TSPSOURCEARCHIVE)
        .ifPresent(value -> {
          LOGGER.info("Overriding configuration value: setting TSP source for archive timestamps: {}", value);
          configuration.setTspSourceForArchiveTimestamps(value);
        });
    getExecOptionValue(ExecutionOption.DATST)
        .map(DigestAlgorithm::valueOf)
        .ifPresent(value -> {
          LOGGER.info("Overriding configuration value: setting archive timestamp digest algorithm: {}", value.name());
          configuration.setArchiveTimestampDigestAlgorithm(value);
        });
    getExecOptionValue(ExecutionOption.REFDATST)
        .map(DigestAlgorithm::valueOf)
        .ifPresent(value -> {
          LOGGER.info("Overriding configuration value: setting archive timestamp reference digest algorithm: {}", value.name());
          configuration.setArchiveTimestampReferenceDigestAlgorithm(value);
        });
  }

  private Optional<String> getExecOptionValue(ExecutionOption execOpt) {
    if (context.getCommandLine().hasOption(execOpt.getName())) {
      String val = context.getCommandLine().getOptionValue(execOpt.getName());
      return StringUtils.isNotBlank(val) ? Optional.of(val) : Optional.empty();
    }
    return Optional.empty();
  }

  private boolean hasAnyOption(String... opts) {
    return Arrays.stream(opts).anyMatch(opt -> context.getCommandLine().hasOption(opt));
  }

  public ExecutionContext getContext() {
    return context;
  }

}
