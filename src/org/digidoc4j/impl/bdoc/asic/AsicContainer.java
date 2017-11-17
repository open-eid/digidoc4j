package org.digidoc4j.impl.bdoc.asic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.digidoc4j.impl.bdoc.BDocSignatureOpener;
import org.digidoc4j.impl.bdoc.manifest.AsicManifest;
import org.digidoc4j.impl.bdoc.xades.SignatureExtender;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

/**
 * Created by Andrei on 7.11.2017.
 */
public abstract class AsicContainer implements Container {

  private static final Logger logger = LoggerFactory.getLogger(AsicContainer.class);
  public static String ASIC_S = "ASICS";
  public static String ASIC_E = "ASICE";
  public static String BDOC = "BDOC";

  protected Configuration configuration;
  private ValidationResult validationResult;

  private List<Signature> newSignatures = new ArrayList<>();
  private List<Signature> allSignatures = new ArrayList<>();
  private List<DataFile> allDataFiles = new ArrayList<>();
  private List<DataFile> newDataFiles = new ArrayList<>();
  private AsicParseResult containerParseResult;
  private boolean dataFilesHaveChanged;
  private String containerType = "";

  protected abstract String createUserAgent();

  public AsicContainer(){
    configuration = Configuration.getInstance();
  }

  public AsicContainer(Configuration configuration) {
    this.configuration = configuration;
  }

  public AsicContainer(String containerPath){
    configuration = Configuration.getInstance();
    openContainer(containerPath);
  }

  public AsicContainer(String containerPath, Configuration configuration){
    this.configuration = configuration;
    openContainer(containerPath);
  }

  public AsicContainer(InputStream stream){
    configuration = Configuration.getInstance();
    openContainer(stream);
  }

  public AsicContainer(InputStream stream, Configuration configuration){
    this.configuration = configuration;
    openContainer(stream);
  }

  @Override
  public ValidationResult validate() {
    if (validationResult == null) {
      validationResult = validateContainer();
    }
    return validationResult;
  }

  protected ValidationResult validateContainer() {

    if(!isNewContainer()){
      BDocContainerValidator validator = new BDocContainerValidator(containerParseResult, getConfiguration());
      validator.setValidateManifest(!dataFilesHaveChanged);
      ValidationResult validationResult = validator.validate(getSignatures());
      return validationResult;
    } else{
      return new BDocContainerValidator(getConfiguration()).validate(getSignatures());
    }
  }

  @Override
  public File saveAsFile(String filePath) {
    logger.debug("Saving container to file: " + filePath);
    File file = new File(filePath);
    try (OutputStream stream = Helper.bufferedOutputStream(file)) {
      save(stream);
      logger.info("Container was saved to file " + filePath);
      return file;
    } catch (IOException e) {
      logger.error("Unable to close stream: " + e.getMessage());
      throw new TechnicalException("Unable to close stream", e);
    }
  }

  public Configuration getConfiguration() {
    return configuration;
  }

  protected List<Signature> parseSignatureFiles(List<DSSDocument> signatureFiles, List<DSSDocument> detachedContents) {
    Configuration configuration = getConfiguration();
    BDocSignatureOpener signatureOpener = new BDocSignatureOpener(detachedContents, configuration);
    List<Signature> signatures = new ArrayList<>(signatureFiles.size());
    for (DSSDocument signatureFile : signatureFiles) {
      List<BDocSignature> bDocSignatures = signatureOpener.parse(signatureFile);
      signatures.addAll(bDocSignatures);
    }
    return signatures;
  }

  @Override
  public InputStream saveAsStream() {
    logger.debug("Saving container as stream");
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    save(outputStream);
    InputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    logger.info("Container was saved to stream");
    return inputStream;
  }

  protected void validateIncomingSignature(Signature signature) {
    if (!(signature instanceof BDocSignature)) {
      throw new TechnicalException("BDoc signature must be an instance of BDocSignature");
    }
  }

  protected List<Signature> extendAllSignatureProfile(SignatureProfile profile, List<Signature> signatures, List<DataFile> dataFiles) {
    logger.info("Extending all signatures' profile to " + profile.name());
    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    List<DSSDocument> detachedContentList = detachedContentCreator.getDetachedContentList();
    SignatureExtender signatureExtender = new SignatureExtender(getConfiguration(), detachedContentList);
    List<DSSDocument> extendedSignatureDocuments = signatureExtender.extend(signatures, profile);
    List<Signature> extendedSignatures = parseSignatureFiles(extendedSignatureDocuments, detachedContentList);
    logger.debug("Finished extending all signatures");
    return extendedSignatures;
  }

  protected void validateDataFilesRemoval() {
    if (!getSignatures().isEmpty()) {
      logger.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    }
  }

  protected void verifyIfAllowedToAddDataFile(String fileName) {
    if (getSignatures().size() > 0) {
      String errorMessage = "Datafiles cannot be added to an already signed container";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    checkForDuplicateDataFile(fileName);
  }

  private void checkForDuplicateDataFile(String fileName) {
    logger.debug("");
    for (DataFile dataFile : getDataFiles()) {
      String dataFileName = dataFile.getName();
      if (StringUtils.equals(dataFileName, fileName)) {
        String errorMessage = "Data file " + fileName + " already exists";
        logger.error(errorMessage);
        throw new DuplicateDataFileException(errorMessage);
      }
    }
  }

  public void setType(String containerType){
    this.containerType = containerType;
  }

  @Override
  public String getType(){
    return containerType;
  }

  private void openContainer(String containerPath) {
    logger.debug("Opening container from " + containerPath);
    AsicParseResult containerParseResult = new AsicFileContainerParser(containerPath, getConfiguration()).read();
    populateContainerWithParseResult(containerParseResult);
  }

  private void openContainer(InputStream inputStream) {
    logger.debug("Opening container from stream");
    AsicParseResult containerParseResult = new AsicStreamContainerParser(inputStream, getConfiguration()).read();
    populateContainerWithParseResult(containerParseResult);
  }

  private void populateContainerWithParseResult(AsicParseResult parseResult) {
    containerParseResult = parseResult;
    getDataFiles().addAll(parseResult.getDataFiles());
    List<DSSDocument> signatureFiles = parseResult.getSignatures();
    List<DSSDocument> detachedContents = parseResult.getDetachedContents();
    List<Signature> bDocSignatures = parseSignatureFiles(signatureFiles, detachedContents);
    allSignatures.addAll(bDocSignatures);
  }

  private void removeExistingSignature(BDocSignature signature) {
    DSSDocument signatureDocument = signature.getSignatureDocument();
    if (signatureDocument == null) {
      return;
    }
    String signatureFileName = signatureDocument.getName();
    removeExistingFileFromContainer(signatureFileName);
  }

  private void removeExistingFileFromContainer(String filePath) {
    logger.debug("Removing file from the container: " + filePath);
    if(containerParseResult != null){
    List<AsicEntry> asicEntries = containerParseResult.getAsicEntries();
    for (AsicEntry entry : asicEntries) {
      String entryFileName = entry.getZipEntry().getName();
      if (StringUtils.equalsIgnoreCase(filePath, entryFileName)) {
        asicEntries.remove(entry);
        logger.debug("File was successfully removed");
        break;
      }
    }
    }
  }

  private void removeAllExistingSignaturesFromContainer() {
    logger.debug("Removing all existing signatures");
    for (Signature signature : allSignatures) {
      removeExistingSignature((BDocSignature) signature);
    }
  }

  private int determineNextSignatureFileIndex() {
    Integer currentUsedSignatureFileIndex = containerParseResult.getCurrentUsedSignatureFileIndex();
    if (currentUsedSignatureFileIndex == null) {
      return 0;
    }
    return currentUsedSignatureFileIndex + 1;
  }

  @Override
  public List<DataFile> getDataFiles() {
    return allDataFiles;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    DataFile dataFile = new DataFile(path, mimeType);
    addDataFile(dataFile);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(InputStream inputStream, String fileName, String mimeType) {
    DataFile dataFile = new DataFile(inputStream, fileName, mimeType);
    addDataFile(dataFile);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    DataFile dataFile = new DataFile(file.getPath(), mimeType);
    addDataFile(dataFile);
    return dataFile;
  }

  @Override
  public void addDataFile(DataFile dataFile) {
    String fileName = dataFile.getName();
    verifyIfAllowedToAddDataFile(fileName);
    if("ASICS".equals(getType())) {
      if (allDataFiles.size() > 1) {
        throw new DigiDoc4JException("DataFile is already exists");
      } else if (newDataFiles.size() > 1) {
        throw new DigiDoc4JException("Not possible to add more than one datafile");
      }
    }
    allDataFiles.add(dataFile);
    newDataFiles.add(dataFile);
    dataFilesHaveChanged = true;
    removeExistingFileFromContainer(AsicManifest.XML_PATH);
  }

  @Override
  public void addSignature(Signature signature) {
    validateIncomingSignature(signature);
    newSignatures.add(signature);
    allSignatures.add(signature);
  }

  //=======================================================

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    if(!isNewContainer()) {
      removeAllExistingSignaturesFromContainer();
      List<Signature> signatures = extendAllSignaturesProfile(profile, allSignatures, allDataFiles);
      allSignatures = signatures;
      newSignatures = new ArrayList<>(signatures);
    } else{
      allSignatures = extendAllSignaturesProfile(profile, allSignatures, allDataFiles);
    }
  }

  private List<Signature> extendAllSignaturesProfile(SignatureProfile profile, List<Signature> signatures, List<DataFile> dataFiles) {
    List<Signature> extendedSignatures;
    if("ASICS".equals(getType())){
      extendedSignatures = extendAllSignatureProfile(profile, signatures, Arrays.asList(dataFiles.get(0)));
    }else{
       extendedSignatures = extendAllSignatureProfile(profile, signatures, dataFiles);
    }
    return extendedSignatures;
  }

  @Override
  public void removeSignature(Signature signature) {
    logger.info("Removing signature " + signature.getId());
    if (!isNewContainer()){
      validateIncomingSignature(signature);
      boolean wasNewlyAddedSignature = newSignatures.remove(signature);
      boolean wasIncludedInContainer = allSignatures.remove(signature);
      if (wasIncludedInContainer && !wasNewlyAddedSignature) {
        logger.debug("This signature was included in the container before the container was opened");
        removeExistingSignature((BDocSignature) signature);
      }
    } else{
      allSignatures.remove(signature);
    }
  }

  @Override
  @Deprecated
  public void removeSignature(int signatureId) {
    logger.debug("Removing signature from index " + signatureId);
    if (!isNewContainer()){
      Signature signature = allSignatures.get(signatureId);
      if (signature != null) {
        removeSignature(signature);
      }
    } else{
      allSignatures.remove(signatureId);
    }

  }

  //method is deprecated in case of new container
  @Override
  public void removeDataFile(String fileName) {
    if(!isNewContainer()) {
      logger.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    } else{
      logger.info("Removing data file: " + fileName);
      validateDataFilesRemoval();

      for (DataFile dataFile : allDataFiles) {
        String name = dataFile.getName();
        if (StringUtils.equals(fileName, name)) {
          allDataFiles.remove(dataFile);
          logger.debug("Data file has been removed");
          return;
        }
      }
      throw new DataFileNotFoundException(fileName);
    }
  }

  @Override
  public void removeDataFile(DataFile file) {
    if(!isNewContainer()){
      logger.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    } else{
      logger.info("Removing data file: " + file.getName());
      validateDataFilesRemoval();
      boolean wasRemovalSuccessful = allDataFiles.remove(file);

      if (!wasRemovalSuccessful) {
        throw new DataFileNotFoundException(file.getName());
      }
    }
  }

  private boolean isNewContainer() {
    return containerParseResult == null;
  }

  @Override
  public List<Signature> getSignatures() {
    return allSignatures;
  }

  protected void writeAsicContainer(AsicContainerCreator zipCreator) {
    String userAgent = createUserAgent();
    zipCreator.setZipComment(userAgent);
    if(!isNewContainer()){
      int nextSignatureFileIndex = determineNextSignatureFileIndex();
      zipCreator.writeExistingEntries(containerParseResult.getAsicEntries());
      if (dataFilesHaveChanged) {
        zipCreator.writeManifest(allDataFiles, getType());
      }
      zipCreator.writeSignatures(newSignatures, nextSignatureFileIndex);
      zipCreator.writeDataFiles(newDataFiles);
      if (StringUtils.isNotBlank(containerParseResult.getZipFileComment())) {
        zipCreator.writeContainerComment(containerParseResult.getZipFileComment());
      }
    } else{
      int startingSignatureFileIndex = 0;
      zipCreator.writeAsiceMimeType(getType());
      zipCreator.writeManifest(allDataFiles, getType());
      zipCreator.writeDataFiles(allDataFiles);
      zipCreator.writeSignatures(allSignatures, startingSignatureFileIndex);
      zipCreator.writeContainerComment(userAgent);
    }
    zipCreator.finalizeZipFile();
  }

  //=============== Deprecated methods ====================

  @Override
  @Deprecated
  public void addRawSignature(byte[] signatureDocument) {
    logger.info("Adding raw signature");
    Signature signature = SignatureBuilder.
        aSignature(this).
        openAdESSignature(signatureDocument);
    addSignature(signature);
  }

  @Override
  @Deprecated
  public void addRawSignature(InputStream signatureStream) {
    try {
      byte[] bytes = IOUtils.toByteArray(signatureStream);
      addRawSignature(bytes);
    } catch (IOException e) {
      logger.error("Failed to read signature stream: " + e.getMessage());
      throw new InvalidSignatureException();
    }
  }

  @Override
  @Deprecated
  public int countDataFiles() {
    return getDataFiles().size();
  }

  @Override
  @Deprecated
  public int countSignatures() {
    return getSignatures().size();
  }

  @Override
  @Deprecated
  public DocumentType getDocumentType() {
    return Container.DocumentType.BDOC;
  }

  @Override
  @Deprecated
  public String getVersion() {
    return "";
  }

  @Override
  @Deprecated
  public void extendTo(SignatureProfile profile) {
    extendSignatureProfile(profile);
  }

  @Override
  @Deprecated
  public void save(String path) {
    saveAsFile(path);
  }

  @Override
  @Deprecated
  public DataFile getDataFile(int index) {
    return getDataFiles().get(index);
  }

  @Override
  @Deprecated
  public Signature getSignature(int index) {
    return getSignatures().get(index);
  }

  /**
   * Prepare signing method is not supported by BDoc container.
   *
   * @param signerCert X509 Certificate to be used for preparing the signature
   * @return NotSupportedException
   */

  @Override
  @Deprecated
  public SignedInfo prepareSigning(X509Certificate signerCert) {
    throw new NotSupportedException("Prepare signing method is not supported by BDoc container");
  }

  /**
   *  Getting signature profile method is not supported by BDoc container.
   *
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public String getSignatureProfile() {
    throw new NotSupportedException("Getting signature profile method is not supported by BDoc container");
  }

  /**
   * Setting signature parameters method is not supported by BDoc container
   *
   * @param signatureParameters Signature parameters. These are  related to the signing location and signer roles
   */
  @Override
  @Deprecated
  public void setSignatureParameters(SignatureParameters signatureParameters) {
    throw new NotSupportedException("Setting signature parameters method is not supported by BDoc container");
  }

  /**
   * Getting digest algorithm method is not supported by BDoc container.
   *
   * @return NotSupportedException.
   */
  @Override
  @Deprecated
  public DigestAlgorithm getDigestAlgorithm() {
    throw new NotSupportedException("Getting digest algorithm method is not supported by BDoc container");
  }

  /**
   * Sign method is not supported by BDoc container.
   *
   * @param signatureToken signatureToken implementation
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public Signature sign(SignatureToken signatureToken) {
    throw new NotSupportedException("Sign method is not supported by BDoc container");
  }

  /**
   * Sign raw method is not supported by BDoc container.
   *
   * @param rawSignature raw signature
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public Signature signRaw(byte[] rawSignature) {
    throw new NotSupportedException("Sign raw method is not supported by BDoc container");
  }

  /**
   * Setting signature profile method is not supported by BDoc container.
   *
   * @param profile signature profile
   */
  @Override
  @Deprecated
  public void setSignatureProfile(SignatureProfile profile) {
    throw new NotSupportedException("Setting signature profile method is not supported by BDoc container");
  }
}