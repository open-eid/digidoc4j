/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.impl.bdoc.asic.AsicContainerParser;
import org.digidoc4j.impl.bdoc.asic.AsicEntry;
import org.digidoc4j.impl.bdoc.asic.AsicParseResult;
import org.digidoc4j.impl.bdoc.asic.BDocContainerValidator;
import org.digidoc4j.impl.bdoc.xades.SignatureExtender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

public class ExistingBDocContainer extends BDocContainer {

  private static final Logger logger = LoggerFactory.getLogger(ExistingBDocContainer.class);
  private List<Signature> existingSignatures = new ArrayList<>();
  private List<Signature> newSignatures = new ArrayList<>();
  private List<Signature> allSignatures = new ArrayList<>();
  private List<DataFile> allDataFiles = new ArrayList<>();
  private List<DataFile> newDataFiles = new ArrayList<>();
  private AsicParseResult containerParseResult;
  private boolean dataFilesHaveChanged;

  public ExistingBDocContainer(String containerPath) {
    openContainer(containerPath);
  }

  public ExistingBDocContainer(String containerPath, Configuration configuration) {
    super(configuration);
    openContainer(containerPath);
  }

  public ExistingBDocContainer(InputStream stream) {
    openContainer(stream);
  }

  public ExistingBDocContainer(InputStream stream, Configuration configuration) {
    super(configuration);
    openContainer(stream);
  }

  @Override
  protected ValidationResult validateContainer() {
    BDocContainerValidator validator = new BDocContainerValidator(containerParseResult);
    validator.setValidateManifest(!dataFilesHaveChanged);
    ValidationResult validationResult = validator.validate(getSignatures());
    return validationResult;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    String fileName = new File(path).getName();
    DataFile dataFile = new DataFile(path, mimeType);
    addDataFile(dataFile, fileName);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(InputStream inputStream, String fileName, String mimeType) {
    fileName = new File(fileName).getName();
    DataFile dataFile = new DataFile(inputStream, fileName, mimeType);
    addDataFile(dataFile, fileName);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    DataFile dataFile = new DataFile(file.getPath(), mimeType);
    addDataFile(dataFile, file.getName());
    return dataFile;
  }

  @Override
  public void addDataFile(DataFile dataFile) {
    String fileName = dataFile.getName();
    addDataFile(dataFile, fileName);
  }

  @Override
  public void addSignature(Signature signature) {
    validateIncomingSignature(signature);
    newSignatures.add(signature);
    allSignatures.add(signature);
  }

  @Override
  public List<DataFile> getDataFiles() {
    return allDataFiles;
  }

  @Override
  public List<Signature> getSignatures() {
    return allSignatures;
  }

  @Override
  public void removeDataFile(String fileName) {
    logger.error("Datafiles cannot be removed from an already signed container");
    throw new RemovingDataFileException();
  }

  @Override
  public void removeDataFile(DataFile file) {
    logger.error("Datafiles cannot be removed from an already signed container");
    throw new RemovingDataFileException();
  }

  @Override
  public void removeSignature(Signature signature) {
    logger.info("Removing signature " + signature.getId());
    validateIncomingSignature(signature);
    boolean wasNewlyAddedSignature = newSignatures.remove(signature);
    boolean wasIncludedInContainer = allSignatures.remove(signature);
    if (wasIncludedInContainer && !wasNewlyAddedSignature) {
      logger.debug("This signature was included in the container before the container was opened");
      removeExistingSignature((BDocSignature) signature);
    }
  }

  @Override
  @Deprecated
  public void removeSignature(int signatureId) {
    logger.debug("Removing signature from index " + signatureId);
    Signature signature = allSignatures.get(signatureId);
    if (signature != null) {
      removeSignature(signature);
    }
  }

  protected AsicParseResult getContainerParseResult() {
    return containerParseResult;
  }

  protected List<DataFile> getNewDataFiles() {
    return newDataFiles;
  }

  protected List<Signature> getNewSignatures() {
    return newSignatures;
  }

  protected int determineNextSignatureFileIndex() {
    Integer currentUsedSignatureFileIndex = containerParseResult.getCurrentUsedSignatureFileIndex();
    if (currentUsedSignatureFileIndex == null) {
      return 0;
    }
    return currentUsedSignatureFileIndex + 1;
  }

  protected void writeAsicContainer(AsicContainerCreator zipCreator) {
    AsicParseResult containerParseResult = getContainerParseResult();
    Collection<Signature> newSignatures = getNewSignatures();
    Collection<DataFile> newDataFiles = getNewDataFiles();
    int nextSignatureFileIndex = determineNextSignatureFileIndex();
    Collection<DataFile> dataFiles = getDataFiles();
    zipCreator.writeExistingEntries(containerParseResult.getAsicEntries());
    zipCreator.writeManifest(dataFiles);
    zipCreator.writeSignatures(newSignatures, nextSignatureFileIndex);
    zipCreator.writeDataFiles(newDataFiles);
    if (StringUtils.isNotBlank(containerParseResult.getZipFileComment())) {
      zipCreator.writeContainerComment(containerParseResult.getZipFileComment());
    }
    zipCreator.finalizeZipFile();
  }

  private void openContainer(String containerPath) {
    logger.debug("Opening container from " + containerPath);
    AsicParseResult containerParseResult = new AsicContainerParser(containerPath).read();
    populateContainerWithParseResult(containerParseResult);
  }

  private void openContainer(InputStream inputStream) {
    logger.debug("Opening container from stream");
    AsicParseResult containerParseResult = new AsicContainerParser(inputStream).read();
    populateContainerWithParseResult(containerParseResult);
  }

  private void populateContainerWithParseResult(AsicParseResult parseResult) {
    containerParseResult = parseResult;
    getDataFiles().addAll(parseResult.getDataFiles());
    List<DSSDocument> signatureFiles = parseResult.getSignatures();
    List<DSSDocument> detachedContents = parseResult.getDetachedContents();
    parseSignatureFiles(signatureFiles, detachedContents);
  }

  private void parseSignatureFiles(List<DSSDocument> signatureFiles, List<DSSDocument> detachedContents) {
    Configuration configuration = getConfiguration();
    BDocSignatureOpener signatureOpener = new BDocSignatureOpener(detachedContents, configuration);
    for (DSSDocument signatureFile : signatureFiles) {
      List<BDocSignature> bDocSignatures = signatureOpener.parse(signatureFile);
      existingSignatures.addAll(bDocSignatures);
      allSignatures.addAll(bDocSignatures);
    }
  }

  private void addDataFile(DataFile dataFile, String fileName) {
    verifyIfAllowedToAddDataFile(fileName);
    allDataFiles.add(dataFile);
    newDataFiles.add(dataFile);
    dataFilesHaveChanged = true;
  }

  private void removeExistingSignature(BDocSignature signature) {
    DSSDocument signatureDocument = signature.getSignatureDocument();
    if (signatureDocument == null) {
      return;
    }
    String signatureFileName = signatureDocument.getName();
    removeExistingFileFromContainer(signatureFileName);
  }

  private void removeExistingFileFromContainer(String fileName) {
    List<AsicEntry> asicEntries = containerParseResult.getAsicEntries();
    for (AsicEntry entry : asicEntries) {
      String entryFileName = entry.getContent().getName();
      if (StringUtils.equalsIgnoreCase(fileName, entryFileName)) {
        logger.debug("Removing file from the container: " + fileName);
        asicEntries.remove(entry);
      }
    }
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    logger.info("Extending all signatures' profile to " + profile.name());
    validatePossibilityToExtendTo(profile);
    List<DSSDocument> signaturesToExtend = containerParseResult.getSignatures();
    DSSDocument detachedContent = containerParseResult.getDetachedContent();
    SignatureExtender signatureExtender = new SignatureExtender(getConfiguration(), detachedContent);
    List<DSSDocument> extendedSignatures = signatureExtender.extend(signaturesToExtend, profile);
    existingSignatures.clear();
    allSignatures.clear();
    parseSignatureFiles(extendedSignatures, containerParseResult.getDetachedContents());
  }
}
