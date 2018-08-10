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

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.asics.AsicSContainer;
import org.digidoc4j.impl.pades.PadesContainer;
import org.digidoc4j.signers.PKCS11SignatureToken;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.signers.TimestampToken;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * Class for managing digidoc4j-util parameters.
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
    if (container instanceof PadesContainer) {
      this.verifyPadesContainer(container);
    } else {
      this.manipulateContainer(container);
      if (Container.DocumentType.ASICS.equals(this.getContainerType()) && this.isOptionsToSignAndAddFile()) {
        AsicSContainer asicSContainer = (AsicSContainer) container;
        this.verifyIfAllowedToAddSignature(asicSContainer);
        this.signAsicSContainer(asicSContainer);
      } else {
        this.signContainer(container);
      }
      this.verifyContainer(container);
    }
  }

  /**
   * @return indication whether this executor has internal command found
   */
  public boolean hasCommand() {
    return this.context.getCommand() != null;
  }

  /**
   * Executes internal command
   */
  public void executeCommand() {
    if (this.hasCommand()) {
      for (ExecutionOption option : this.context.getCommand().getMandatoryOptions()) {
        switch (option) {
          case IN:
            this.context.setContainer(this.openContainer(this.context.getCommandLine().getOptionValue(option.getName())));
            break;
          case ADD:
            try {
              this.context.getContainer();
            } catch (DigiDoc4JException ignored) {
              this.context.setContainer(this.openContainer());
            }
            this.addData();
            break;
          case CERTIFICATE:
            this.context.setCertificate(this.loadCertificate());
            break;
          case DTS:
            switch (this.context.getCommand()) {
              case EXTERNAL_COMPOSE_DTS:
                this.context.setDataToSign(this.createSigningData());
                break;
              case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS11:
              case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS12:
                this.context.setDataToSign(this.loadSigningData());
                break;
              case EXTERNAL_ADD_SIGNATURE:
                this.context.setDataToSign(this.loadSigningData());
                break;
            }
            break;
          case PKCS11:
            this.context.setSignatureToken(this.loadPKCS11Token());
            break;
          case PKCS12:
            this.context.setSignatureToken(this.loadPKCS12Token());
            break;
          case SIGNATURE:
            switch (this.context.getCommand()) {
              case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS11:
              case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS12:
                this.context.setSignature(this.createSignature());
                break;
              case EXTERNAL_ADD_SIGNATURE:
                this.context.setSignature(this.loadSignature());
            }
            break;
          default:
            LOGGER.warn("No option <{}> implemented", option);
        }
      }
      this.postExecutionProcess();
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
    if (StringUtils.equalsIgnoreCase(this.context.getCommandLine().getOptionValue("type"), "BDOC"))
      return Container.DocumentType.BDOC;
    if (StringUtils.equalsIgnoreCase(this.context.getCommandLine().getOptionValue("type"), "ASICS"))
      return Container.DocumentType.ASICS;
    if (StringUtils.equalsIgnoreCase(this.context.getCommandLine().getOptionValue("type"), "ASICE"))
      return Container.DocumentType.ASICE;
    if (StringUtils.equalsIgnoreCase(this.context.getCommandLine().getOptionValue("type"), "DDOC"))
      return Container.DocumentType.DDOC;
    if (StringUtils.endsWithIgnoreCase(this.context.getCommandLine().getOptionValue("in"), ".bdoc"))
      return Container.DocumentType.BDOC;
    if (StringUtils.endsWithIgnoreCase(this.context.getCommandLine().getOptionValue("in"), ".asics"))
      return Container.DocumentType.ASICS;
    if (StringUtils.endsWithIgnoreCase(this.context.getCommandLine().getOptionValue("in"), ".scs"))
      return Container.DocumentType.ASICS;
    if (StringUtils.endsWithIgnoreCase(this.context.getCommandLine().getOptionValue("in"), ".asice"))
      return Container.DocumentType.ASICE;
    if (StringUtils.endsWithIgnoreCase(this.context.getCommandLine().getOptionValue("in"), ".sce"))
      return Container.DocumentType.ASICE;
    if (StringUtils.endsWithIgnoreCase(this.context.getCommandLine().getOptionValue("in"), ".ddoc"))
      return Container.DocumentType.DDOC;
    if (StringUtils.endsWithIgnoreCase(this.context.getCommandLine().getOptionValue("in"), ".pdf"))
      return Container.DocumentType.PADES;
    return Container.DocumentType.BDOC;
  }

  /**
   * @return generated container
   */
  public Container openContainer() {
    return this.openContainer("");
  }

  /**
   * @param containerPath path
   * @return existing or generated container
   */
  public Container openContainer(String containerPath) {
    Container.DocumentType type = this.getContainerType();
    if (new File(containerPath).exists() || this.context.getCommandLine().hasOption("verify") || this.context.getCommandLine().hasOption("remove")) {
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
    if (this.fileHasChanged) {
      container.saveAsFile(containerPath);
      if (new File(containerPath).exists()) {
        LOGGER.debug("Container has been successfully saved to " + containerPath);
      } else {
        LOGGER.warn("Container was NOT saved to " + containerPath);
      }
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private void verifyIfAllowedToAddSignature(AsicSContainer asicSContainer) {
    if (asicSContainer.isTimestampTokenDefined()) {
      throw new DigiDoc4JException("This container has already timestamp. Should be no signatures in case of timestamped ASiCS container.");
    }
    if (!asicSContainer.getSignatures().isEmpty()) {
      throw new DigiDoc4JException("This container is already signed. Should be only one signature in case of ASiCS container.");
    }
  }

  private boolean isOptionsToSignAndAddFile() {
    return this.context.getCommandLine().hasOption("add") || this.context.getCommandLine().hasOption("pkcs11") || this.context.getCommandLine().hasOption("pkcs12");
  }

  private void signAsicSContainer(AsicSContainer asicSContainer) {
    if (this.context.getCommandLine().hasOption("tst")) {
      this.signContainerWithTst(asicSContainer);
    } else {
      this.signContainer(asicSContainer);
    }
  }

  private void manipulateContainer(Container container) {
    if (this.context.getCommandLine().hasOption(ExecutionOption.ADD.getName())) {
      this.addData(container);
    }
    if (this.context.getCommandLine().hasOption("remove")) {
      container.removeDataFile(this.context.getCommandLine().getOptionValue("remove"));
      this.fileHasChanged = true;
    }
    if (this.context.getCommandLine().hasOption(ExecutionOption.EXTRACT.getName())) {
      LOGGER.debug("Extracting data file");
      this.extractDataFile(container);
    }
  }

  private void addData() {
    this.addData(this.context.getContainer());
  }

  private void addData(Container container) {
    LOGGER.debug("Adding data to container ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.ADD.getName());
    container.addDataFile(values[0], values[1]);
    this.fileHasChanged = true;
  }

  private DataToSign createSigningData() {
    LOGGER.debug("Creating signing data ...");
    return SignatureBuilder.aSignature(this.context.getContainer()).withSigningCertificate(this.context.getCertificate())
        .withSignatureDigestAlgorithm(this.context.getDigestAlgorithm()).buildDataToSign();
  }

  private byte[] createSignature() {
    LOGGER.debug("Creating signature ...");
    return this.context.getSignatureToken().sign(this.context.getDigestAlgorithm(), this.context.getDataToSign().getDataToSign());
  }

  private X509Certificate loadCertificate() {
    LOGGER.debug("Loading certificate ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.CERTIFICATE.getName());
    try (InputStream stream = new FileInputStream(values[0])) {
      return DSSUtils.loadCertificate(stream).getCertificate();
    } catch (IOException e) {
      throw new DigiDoc4JException(String.format("Unable to load certificate file from <%s>", values[0]), e);
    }
  }

  private DataToSign loadSigningData() {
    LOGGER.debug("Loading signing data ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.DTS.getName());
    try {
      return Helper.deserializer(values[0]);
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to load signing data file from <%s>", values[0]), e);
    }
  }

  private byte[] loadSignature() {
    LOGGER.debug("Loading signature ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.SIGNATURE.getName());
    try {
      return Files.readAllBytes(Paths.get(values[0]));
    } catch (IOException e) {
      throw new DigiDoc4JException(String.format("Unable to load signature file from <%s>", values[0]), e);
    }
  }

  private SignatureToken loadPKCS11Token() {
    LOGGER.debug("Loading PKCS11 token ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.PKCS11.getName());
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

  private void storeSignature() {
    LOGGER.debug("Storing signature ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.SIGNATURE.getName());
    try (OutputStream stream = new FileOutputStream(values[0])) {
      IOUtils.write(this.context.getSignature(), stream);
    } catch (IOException e) {
      throw new DigiDoc4JException(String.format("Unable to store signature file to <%s>", values[0]), e);
    }
  }

  private void storeSigningData() {
    LOGGER.debug("Storing signing data ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.DTS.getName());
    try {
      Helper.serialize(this.context.getDataToSign(), values[0]);
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to store signing data file to <%s>", values[0]), e);
    }
  }

  private void storeContainer() {
    LOGGER.debug("Storing container ...");
    String[] values = this.context.getCommandLine().getOptionValues(ExecutionOption.IN.getName());
    try {
      this.context.getContainer().saveAsFile(values[0]);
    } catch (Exception e) {
      throw new DigiDoc4JException(String.format("Unable to store container file to <%s>", values[0]), e);
    }
  }

  private void storeContainerWithSignature() {
    LOGGER.debug("Adding signature to container ...");
    Container container = this.context.getContainer();
    container.addSignature(this.context.getDataToSign().finalize(this.context.getSignature()));
    this.fileHasChanged = true;
    this.saveContainer(container, this.context.getCommandLine().getOptionValue(ExecutionOption.IN.getName()));
  }

  private void postExecutionProcess() {
    switch (this.context.getCommand()) {
      case EXTERNAL_COMPOSE_DTS:
        this.storeSigningData();
        this.storeContainer();
        break;
      case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS11:
      case EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS12:
        this.storeSignature();
        break;
      case EXTERNAL_ADD_SIGNATURE:
        this.storeContainerWithSignature();
        break;
    }
  }

  private void extractDataFile(Container container) {
    String[] optionValues = this.context.getCommandLine().getOptionValues(ExecutionOption.EXTRACT.getName());
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

  private void signContainer(Container container) {
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);
    this.updateProfile(signatureBuilder);
    this.updateEncryptionAlgorithm(signatureBuilder);
    this.signWithPkcs12(container, signatureBuilder);
    this.signWithPkcs11(container, signatureBuilder);
  }

  private void updateProfile(SignatureBuilder signatureBuilder) {
    if (this.context.getCommandLine().hasOption("profile")) {
      String profile = this.context.getCommandLine().getOptionValue("profile");
      try {
        SignatureProfile signatureProfile = SignatureProfile.valueOf(profile);
        signatureBuilder.withSignatureProfile(signatureProfile);
      } catch (IllegalArgumentException e) {
        System.out.println("Signature profile \"" + profile + "\" is unknown and will be ignored");
      }
    }
  }

  private void updateEncryptionAlgorithm(SignatureBuilder signatureBuilder) {
    if (this.context.getCommandLine().hasOption("encryption")) {
      String encryption = this.context.getCommandLine().getOptionValue("encryption");
      EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.valueOf(encryption);
      signatureBuilder.withEncryptionAlgorithm(encryptionAlgorithm);
    }
  }

  private void signWithPkcs12(Container container, SignatureBuilder signatureBuilder) {
    if (this.context.getCommandLine().hasOption("pkcs12")) {
      String[] optionValues = this.context.getCommandLine().getOptionValues("pkcs12");
      SignatureToken pkcs12Signer = new PKCS12SignatureToken(optionValues[0], optionValues[1].toCharArray());
      Signature signature = invokeSigning(signatureBuilder, pkcs12Signer);
      container.addSignature(signature);
      this.fileHasChanged = true;
    }
  }

  private void signContainerWithTst(AsicContainer asicContainer) {
    if (this.context.getCommandLine().hasOption("tst") && !(this.context.getCommandLine().hasOption("pkcs12") || this.context.getCommandLine().hasOption("pkcs11"))) {
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
      if (this.context.getCommandLine().hasOption("datst")) {
        String digestAlgorithmStr = this.context.getCommandLine().getOptionValue("datst");
        if (StringUtils.isNotBlank(digestAlgorithmStr)) {
          digestAlgorithm = DigestAlgorithm.forName(digestAlgorithmStr);
        }
      }
      LOGGER.info("Digest algorithm to calculate data file hash: " + digestAlgorithm.getName());
      if (this.context.getCommandLine().hasOption("add")) {
        if (asicContainer.getDataFiles().size() > 1) {
          throw new DigiDoc4JException("Data file in container already exists. Should be only one data file in case of ASiCS container.");
        }
        String[] optionValues = this.context.getCommandLine().getOptionValues("add");
        DataFile dataFile = new DataFile(optionValues[0], optionValues[1]);
        DataFile tst = TimestampToken.generateTimestampToken(digestAlgorithm, dataFile);
        asicContainer.setTimeStampToken(tst);
        this.fileHasChanged = true;
      }
    }
  }

  private void signWithPkcs11(Container container, SignatureBuilder signatureBuilder) {
    if (this.context.getCommandLine().hasOption("pkcs11")) {
      String[] optionValues = this.context.getCommandLine().getOptionValues("pkcs11");
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
      Signature signature = this.invokeSigning(signatureBuilder, pkcs11Signer);
      container.addSignature(signature);
      this.fileHasChanged = true;
    }
  }

  private Signature invokeSigning(SignatureBuilder signatureBuilder, SignatureToken signatureToken) {
    return signatureBuilder.withSignatureToken(signatureToken).invokeSigning();
  }

  private void verifyContainer(Container container) {
    Path reports = null;
    if (this.context.getCommandLine().hasOption("reportDir")) {
      reports = Paths.get(this.context.getCommandLine().getOptionValue("reportDir"));
    }
    if (this.context.getCommandLine().hasOption("verify")) {
      ContainerVerifier verifier = new ContainerVerifier(this.context.getCommandLine());
      if (this.context.getCommandLine().hasOption("showerrors")){
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

  /*
   * ACCESSORS
   */

  public ExecutionContext getContext() {
    return context;
  }

}