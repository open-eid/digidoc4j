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
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.impl.bdoc.asic.BDocContainerValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Offers functionality for handling new BDoc container data files and signatures in a container.
 */
public class NewBDocContainer extends BDocContainer {

  private static final Logger logger = LoggerFactory.getLogger(NewBDocContainer.class);
  private List<Signature> signatures = new ArrayList<>();
  private List<DataFile> dataFiles = new ArrayList<>();

  /**
   * NewBDocContainer constructor. Instantiating existing NewBDoc container.
   */
  public NewBDocContainer() {
  }

  /**
   * NewBDocContainer constructor. Instantiating existing NewBDoc container with configuration.
   *
   * @param configuration
   */
  public NewBDocContainer(Configuration configuration) {
    super(configuration);
  }

  @Override
  protected ValidationResult validateContainer() {
    return new BDocContainerValidator(getConfiguration()).validate(getSignatures());
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    signatures = extendAllSignaturesProfile(profile, signatures, dataFiles);
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
    verifyIfAllowedToAddDataFile(dataFile.getName());
    getDataFiles().add(dataFile);
  }

  @Override
  public List<DataFile> getDataFiles() {
    return dataFiles;
  }

  @Override
  public void addSignature(Signature signature) {
    validateIncomingSignature(signature);
    signatures.add(signature);
  }

  @Override
  public List<Signature> getSignatures() {
    return signatures;
  }

  @Override
  public void removeSignature(Signature signature) {
    signatures.remove(signature);
  }

  @Override
  @Deprecated
  public void removeSignature(int signatureId) {
    signatures.remove(signatureId);
  }

  @Override
  public void removeDataFile(DataFile file) {
    logger.info("Removing data file: " + file.getName());
    validateDataFilesRemoval();
    boolean wasRemovalSuccessful = dataFiles.remove(file);

    if (!wasRemovalSuccessful) {
      throw new DataFileNotFoundException(file.getName());
    }
  }

  @Override
  @Deprecated
  public void removeDataFile(String fileName) {
    logger.info("Removing data file: " + fileName);
    validateDataFilesRemoval();

    for (DataFile dataFile : dataFiles) {
      String name = dataFile.getName();
      if (StringUtils.equals(fileName, name)) {
        dataFiles.remove(dataFile);
        logger.debug("Data file has been removed");
        return;
      }
    }

    throw new DataFileNotFoundException(fileName);
  }

  protected void writeAsicContainer(AsicContainerCreator zipCreator) {
    int startingSignatureFileIndex = 0;
    String userAgent = createUserAgent();
    zipCreator.setZipComment(userAgent);
    zipCreator.writeAsiceMimeType();
    zipCreator.writeManifest(dataFiles);
    zipCreator.writeDataFiles(dataFiles);
    zipCreator.writeSignatures(signatures, startingSignatureFileIndex);
    zipCreator.writeContainerComment(userAgent);
    zipCreator.finalizeZipFile();
  }

}
