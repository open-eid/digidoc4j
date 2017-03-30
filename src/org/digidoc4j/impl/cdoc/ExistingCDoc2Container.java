package org.digidoc4j.impl.cdoc;

import java.io.File;
import java.io.InputStream;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.EncryptedDataFile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.impl.bdoc.BDocCrypto;
import org.digidoc4j.impl.bdoc.BDocCryptoRecipientsFile;
import org.digidoc4j.impl.bdoc.BDocCryptoRecipientsFileReader;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.impl.bdoc.asic.AsicEntry;
import org.digidoc4j.impl.bdoc.asic.AsicFileContainerParser;
import org.digidoc4j.impl.bdoc.asic.AsicParseResult;
import org.digidoc4j.impl.bdoc.asic.AsicStreamContainerParser;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Iterables;

/**
 * Created by Kaarel Raspel on 22/03/17.
 */
public class ExistingCDoc2Container extends CDoc2Container {

  private static final Logger logger = LoggerFactory.getLogger(ExistingCDoc2Container.class);

  ExistingCDoc2Container() {}

  public ExistingCDoc2Container(String containerPath) {
    openContainer(containerPath);
  }

  public ExistingCDoc2Container(String containerPath, Configuration configuration) {
    super(configuration);
    openContainer(containerPath);
  }

  public ExistingCDoc2Container(InputStream stream) {
    openContainer(stream);
  }

  public ExistingCDoc2Container(InputStream stream, Configuration configuration) {
    super(configuration);
    openContainer(stream);
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
    List<DataFile> dataFiles = parseResult.getDataFiles();
    populateBDocCrypto(dataFiles, parseResult.getAsicEntries());
    getDataFiles().addAll(dataFiles);
  }

  private void populateBDocCrypto(List<DataFile> dataFiles, List<AsicEntry> asicEntries) {
    AsicEntry recipientsEntry = findAsicEntryByName(asicEntries, BDocCryptoRecipientsFile.XML_PATH);
    if (recipientsEntry != null) {
      BDocCryptoRecipientsFile bDocCryptoRecipientsFile = new BDocCryptoRecipientsFileReader().read(recipientsEntry.getContent().openStream());
      bDocCrypto = new BDocCrypto(this, bDocCryptoRecipientsFile);

      List<String> encryptedFileNames = bDocCryptoRecipientsFile.getEncrypedFileNames();
      dataFilesConversion(dataFiles, encryptedFileNames);
    }
  }

  private static void dataFilesConversion(List<DataFile> dataFiles, List<String> encryptedFileNames) {
    if (!encryptedFileNames.isEmpty()) {
      for (DataFile dataFile : dataFiles) {
        if (Iterables.contains(encryptedFileNames, dataFile.getDocument().getName())) {
          int index = dataFiles.indexOf(dataFile);
          dataFiles.set(index, new EncryptedDataFile(
              dataFile.getStream(),
              dataFile.getDocument().getName(),
              dataFile.getMediaType())
          );
        }
      }
    }
  }

  private static AsicEntry findAsicEntryByName(List<AsicEntry> asicEntries, String name) {
    for (AsicEntry asicEntry : asicEntries) {
      if (asicEntry.getZipEntry().getName().equalsIgnoreCase(name)) {
        return asicEntry;
      }
    }
    return null;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    DataFile dataFile = new DataFile(path, mimeType);
    addDataFile(dataFile);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    DataFile dataFile = new DataFile(is, fileName, mimeType);
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
    checkForDuplicateDataFile(dataFile.getName());
    getDataFiles().add(dataFile);
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

  @Override
  public String getType() {
    return "CDOC2";
  }

  @Override
  public void removeDataFile(DataFile file) {
    if (!getDataFiles().remove(file)) {
      logger.debug("Could not remove non-existing datafile from the container");
    }
  }

  @Override
  public File saveAsFile(String filePath) {
    logger.debug("Saving container to file: " + filePath);
    File file = new File(filePath);
    AsicContainerCreator zipCreator = new AsicContainerCreator(file);
    writeAsicContainer(zipCreator);
    logger.info("Container was saved to file " + filePath);
    return file;
  }

  @Override
  public InputStream saveAsStream() {
    logger.debug("Saving container as stream");
    AsicContainerCreator zipCreator = new AsicContainerCreator();
    writeAsicContainer(zipCreator);
    InputStream inputStream = zipCreator.fetchInputStreamOfFinalizedContainer();
    logger.info("Container was saved to stream");
    return inputStream;
  }

  @Override
  public ValidationResult validate() {
    return null;
  }

  @Override
  public List<EncryptedDataFile> getEncryptedDataFiles() {
    return bDocCrypto.getEncryptedDataFiles();
  }

  @Override
  public List<DataFile> getPlainDataFiles() {
    return bDocCrypto.getPlainDataFiles();
  }

  @Override
  public EncryptedDataFile encryptDataFile(DataFile dataFile) {
    return bDocCrypto.encryptDataFile(dataFile);
  }

  @Override
  public DataFile decryptDataFile(DataFile encryptedDataFile) {
    return bDocCrypto.decryptDataFile(encryptedDataFile);
  }

  protected void writeAsicContainer(AsicContainerCreator zipCreator) {
    String userAgent = Helper.createBDocUserAgent();
    zipCreator.setZipComment(userAgent);
    zipCreator.writeAsiceMimeType();

    zipCreator.writeManifest(getDataFiles());
    zipCreator.writeDataFiles(getPlainDataFiles());
    bDocCrypto.writeToAsicContainer(zipCreator);

    zipCreator.finalizeZipFile();
  }
}
