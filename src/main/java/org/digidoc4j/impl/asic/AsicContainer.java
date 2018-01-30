package org.digidoc4j.impl.asic;

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
import org.digidoc4j.Constant;
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
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerValidator;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureOpener;
import org.digidoc4j.impl.asic.asics.AsicSSignature;
import org.digidoc4j.impl.asic.manifest.AsicManifest;
import org.digidoc4j.impl.asic.xades.SignatureExtender;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

/**
 * Created by Andrei on 7.11.2017.
 */
public abstract class AsicContainer implements Container {

  protected Configuration configuration;
  private final Logger log = LoggerFactory.getLogger(AsicContainer.class);
  private List<DataFile> dataFiles = new ArrayList<>();
  private List<Signature> newSignatures = new ArrayList<>();
  private List<Signature> signatures = new ArrayList<>();
  private List<DataFile> newDataFiles = new ArrayList<>();
  private AsicParseResult containerParseResult;
  private ValidationResult validationResult;
  private boolean dataFilesHaveChanged;
  private String containerType = "";
  private DataFile timeStampToken;

  protected abstract String createUserAgent();

  /**
   * ASicContainer constructor
   */
  public AsicContainer(){
    configuration = Configuration.getInstance();
  }

  /**
   * ASicContainer constructor
   *
   * @param configuration
   */
  public AsicContainer(Configuration configuration) {
    this.configuration = configuration;
  }

  /**
   * ASicContainer constructor
   *
   * @param containerPath
   */
  public AsicContainer(String containerPath){
    configuration = Configuration.getInstance();
    openContainer(containerPath);
  }

  /**
   * ASicContainer constructor
   *
   * @param containerPath
   * @param configuration
   */
  public AsicContainer(String containerPath, Configuration configuration){
    this.configuration = configuration;
    openContainer(containerPath);
  }

  /**
   * ASicContainer constructor
   *
   * @param stream
   */
  public AsicContainer(InputStream stream){
    configuration = Configuration.getInstance();
    openContainer(stream);
  }

  /**
   * ASicContainer constructor
   *
   * @param stream
   * @param configuration
   */
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
    if (timeStampToken != null){
      return validateTimestampToken();
    } else{
      if (!isNewContainer()){
        BDocContainerValidator validator = new BDocContainerValidator(containerParseResult, getConfiguration());
        validator.setValidateManifest(!dataFilesHaveChanged);
        return validator.validate(getSignatures());
      } else{
        return new BDocContainerValidator(getConfiguration()).validate(getSignatures());
      }
    }
  }

  private ValidationResult validateTimestampToken() {
    if (containerParseResult == null){
      containerParseResult = new AsicStreamContainerParser(this.saveAsStream(), getConfiguration()).read();
    }
    TimeStampTokenValidator timeStampTokenValidator = new TimeStampTokenValidator(containerParseResult);
    return timeStampTokenValidator.validate();
  }

  @Override
  public File saveAsFile(String filePath) {
    log.debug("Saving container to file: " + filePath);
    File file = new File(filePath);
    try (OutputStream stream = Helper.bufferedOutputStream(file)) {
      save(stream);
      log.info("Container was saved to file " + filePath);
      return file;
    } catch (IOException e) {
      log.error("Unable to close stream: " + e.getMessage());
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
    log.debug("Saving container as stream");
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    save(outputStream);
    InputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    log.info("Container was saved to stream");
    return inputStream;
  }

  protected void validateIncomingSignature(Signature signature) {
    if (signature == null){
      throw new TechnicalException("ValidateIncomingSignature is null");
    }
    if (!((signature instanceof BDocSignature) || (signature instanceof AsicSSignature) || (signature instanceof AsicESignature)
        || (signature instanceof AsicSignature))) {
      throw new TechnicalException("BDoc signature must be an instance of AsicSignature");
    }
  }

  protected List<Signature> extendAllSignatureProfile(SignatureProfile profile, List<Signature> signatures, List<DataFile> dataFiles) {
    log.info("Extending all signatures' profile to " + profile.name());
    DetachedContentCreator detachedContentCreator = null;
    try {
      detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    } catch (Exception e) {
      log.error("Error in datafiles processing: " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
    List<DSSDocument> detachedContentList = detachedContentCreator.getDetachedContentList();
    SignatureExtender signatureExtender = new SignatureExtender(getConfiguration(), detachedContentList);
    List<DSSDocument> extendedSignatureDocuments = signatureExtender.extend(signatures, profile);
    List<Signature> extendedSignatures = parseSignatureFiles(extendedSignatureDocuments, detachedContentList);
    log.debug("Finished extending all signatures");
    return extendedSignatures;
  }

  protected void validateDataFilesRemoval() {
    if (!getSignatures().isEmpty()) {
      log.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    }
  }

  protected void verifyIfAllowedToAddDataFile(String fileName) {
    if (getSignatures().size() > 0) {
      String errorMessage = "Datafiles cannot be added to an already signed container";
      log.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    checkForDuplicateDataFile(fileName);
  }

  private void checkForDuplicateDataFile(String fileName) {
    log.debug("");
    for (DataFile dataFile : getDataFiles()) {
      String dataFileName = dataFile.getName();
      if (StringUtils.equals(dataFileName, fileName)) {
        String errorMessage = "Data file " + fileName + " already exists";
        log.error(errorMessage);
        throw new DuplicateDataFileException(errorMessage);
      }
    }
  }

  /**
   *
   * @param containerType
   */

  public void setType(String containerType){
    this.containerType = containerType;
  }

  @Override
  public String getType(){
    return containerType;
  }

  private void openContainer(String containerPath) {
    this.log.debug("Opening container from <{}>", containerPath);
    this.populateContainerWithParseResult(new AsicFileContainerParser(containerPath, this.getConfiguration()).read());
  }

  private void openContainer(InputStream inputStream) {
    this.log.debug("Opening container from stream");
    this.populateContainerWithParseResult(new AsicStreamContainerParser(inputStream, this.getConfiguration()).read());
  }

  private void populateContainerWithParseResult(AsicParseResult parseResult) {
    this.containerParseResult = parseResult;
    this.dataFiles.addAll(parseResult.getDataFiles());
    this.timeStampToken = parseResult.getTimeStampToken();
    this.signatures.addAll(this.parseSignatureFiles(parseResult.getSignatures(), parseResult.getDetachedContents()));
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
    log.debug("Removing file from the container: " + filePath);
    if (containerParseResult != null){
    List<AsicEntry> asicEntries = containerParseResult.getAsicEntries();
    for (AsicEntry entry : asicEntries) {
      String entryFileName = entry.getZipEntry().getName();
      if (StringUtils.equalsIgnoreCase(filePath, entryFileName)) {
        asicEntries.remove(entry);
        log.debug("File was successfully removed");
        break;
      }
    }
    }
  }

  private void removeAllExistingSignaturesFromContainer() {
    log.debug("Removing all existing signatures");
    for (Signature signature : signatures) {
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
    return dataFiles;
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
    if (Constant.ASICS_CONTAINER_TYPE.equals(getType())) {
      if (dataFiles.size() > 1) {
        throw new DigiDoc4JException("DataFile is already exists");
      } else if (newDataFiles.size() > 1) {
        throw new DigiDoc4JException("Not possible to add more than one datafile");
      }
    }
    dataFiles.add(dataFile);
    newDataFiles.add(dataFile);
    dataFilesHaveChanged = true;
    removeExistingFileFromContainer(AsicManifest.XML_PATH);
  }

  @Override
  public void addSignature(Signature signature) {
    validateIncomingSignature(signature);
    newSignatures.add(signature);
    signatures.add(signature);
  }

  /**
   * Set timestamp token to container
   *
   * @param timeStampToken
   */
  public void setTimeStampToken(DataFile timeStampToken){
    this.timeStampToken = timeStampToken;
  }

  private byte[] getDigest() {
    DataFile dataFile = getDataFiles().get(0);
    return dataFile.getBytes();
  }

  /**
   * Controlls if timestamp token is defined
   *
   * @return true if timestemp token defined
   */
  public boolean isTimestampTokenDefined(){
    return timeStampToken != null;
  }

  //=======================================================

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    if (!isNewContainer()) {
      removeAllExistingSignaturesFromContainer();
      List<Signature> signatures = extendAllSignaturesProfile(profile, this.signatures, dataFiles);
      this.signatures = signatures;
      newSignatures = new ArrayList<>(signatures);
    } else{
      signatures = extendAllSignaturesProfile(profile, signatures, dataFiles);
    }
  }

  private List<Signature> extendAllSignaturesProfile(SignatureProfile profile, List<Signature> signatures, List<DataFile> dataFiles) {
    List<Signature> extendedSignatures;
    if (Constant.ASICS_CONTAINER_TYPE.equals(getType())){
      extendedSignatures = extendAllSignatureProfile(profile, signatures, Arrays.asList(dataFiles.get(0)));
    } else{
      extendedSignatures = extendAllSignatureProfile(profile, signatures, dataFiles);
    }
    return extendedSignatures;
  }

  @Override
  public void removeSignature(Signature signature) {
    log.info("Removing signature " + signature.getId());
    if (!isNewContainer()){
      validateIncomingSignature(signature);
      boolean wasNewlyAddedSignature = newSignatures.remove(signature);
      boolean wasIncludedInContainer = signatures.remove(signature);
      if (wasIncludedInContainer && !wasNewlyAddedSignature) {
        log.debug("This signature was included in the container before the container was opened");
        removeExistingSignature((BDocSignature) signature);
      }
    } else{
      signatures.remove(signature);
    }
  }

  @Override
  @Deprecated
  public void removeSignature(int signatureId) {
    log.debug("Removing signature from index " + signatureId);
    if (!isNewContainer()){
      Signature signature = signatures.get(signatureId);
      if (signature != null) {
        removeSignature(signature);
      }
    } else{
      signatures.remove(signatureId);
    }

  }

  @Override
  public void removeDataFile(String fileName) {
    if (!isNewContainer()) {
      log.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    } else{
      log.info("Removing data file: " + fileName);
      validateDataFilesRemoval();

      for (DataFile dataFile : dataFiles) {
        String name = dataFile.getName();
        if (StringUtils.equals(fileName, name)) {
          dataFiles.remove(dataFile);
          log.debug("Data file has been removed");
          return;
        }
      }
      throw new DataFileNotFoundException(fileName);
    }
  }

  @Override
  public void removeDataFile(DataFile file) {
    if (!isNewContainer()){
      log.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    } else{
      log.info("Removing data file: " + file.getName());
      validateDataFilesRemoval();
      boolean wasRemovalSuccessful = dataFiles.remove(file);

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
    return signatures;
  }

  protected void writeAsicContainer(AsicContainerCreator zipCreator) {
    String userAgent = createUserAgent();
    zipCreator.setZipComment(userAgent);
    if (!isNewContainer()){
      int nextSignatureFileIndex = determineNextSignatureFileIndex();
      zipCreator.writeExistingEntries(containerParseResult.getAsicEntries());
      if (dataFilesHaveChanged) {
        zipCreator.writeManifest(dataFiles, getType());
      }
      zipCreator.writeSignatures(newSignatures, nextSignatureFileIndex);
      zipCreator.writeDataFiles(newDataFiles);
      if (StringUtils.isNotBlank(containerParseResult.getZipFileComment())) {
        zipCreator.writeContainerComment(containerParseResult.getZipFileComment());
      }
    } else{
      int startingSignatureFileIndex = 0;
      zipCreator.writeAsiceMimeType(getType());
      zipCreator.writeManifest(dataFiles, getType());
      zipCreator.writeDataFiles(dataFiles);
      if (timeStampToken != null && Constant.ASICS_CONTAINER_TYPE.equals(getType())){
        zipCreator.writeTimestampToken(timeStampToken);
      } else {
        zipCreator.writeSignatures(signatures, startingSignatureFileIndex);
      }
      zipCreator.writeContainerComment(userAgent);
    }
    zipCreator.finalizeZipFile();
  }

  //=============== Deprecated methods ====================

  @Override
  @Deprecated
  public void addRawSignature(byte[] signatureDocument) {
    log.info("Adding raw signature");
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
      log.error("Failed to read signature stream: " + e.getMessage());
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
   * Prepare signing method is not supported by ASiC container.
   *
   * @param signerCert X509 Certificate to be used for preparing the signature
   * @return NotSupportedException
   */

  @Override
  @Deprecated
  public SignedInfo prepareSigning(X509Certificate signerCert) {
    throw new NotSupportedException("Prepare signing method is not supported by Asic container");
  }

  /**
   *  Getting signature profile method is not supported by ASiC container.
   *
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public String getSignatureProfile() {
    throw new NotSupportedException("Getting signature profile method is not supported by Asic container");
  }

  /**
   * Setting signature parameters method is not supported by ASiC container
   *
   * @param signatureParameters Signature parameters. These are  related to the signing location and signer roles
   */
  @Override
  @Deprecated
  public void setSignatureParameters(SignatureParameters signatureParameters) {
    throw new NotSupportedException("Setting signature parameters method is not supported by Asic container");
  }

  /**
   * Getting digest algorithm method is not supported by ASiC container.
   *
   * @return NotSupportedException.
   */
  @Override
  @Deprecated
  public DigestAlgorithm getDigestAlgorithm() {
    throw new NotSupportedException("Getting digest algorithm method is not supported by Asic container");
  }

  /**
   * Sign method is not supported by ASiC container.
   *
   * @param signatureToken signatureToken implementation
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public Signature sign(SignatureToken signatureToken) {
    throw new NotSupportedException("Sign method is not supported by Asic container");
  }

  /**
   * Sign raw method is not supported by ASiC container.
   *
   * @param rawSignature raw signature
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public Signature signRaw(byte[] rawSignature) {
    throw new NotSupportedException("Sign raw method is not supported by Asic container");
  }

  /**
   * Setting signature profile method is not supported by ASiC container.
   *
   * @param profile signature profile
   */
  @Override
  @Deprecated
  public void setSignatureProfile(SignatureProfile profile) {
    throw new NotSupportedException("Setting signature profile method is not supported by Asic container");
  }
}
