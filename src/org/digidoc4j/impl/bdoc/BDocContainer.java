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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
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
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.impl.bdoc.asic.DetachedContentCreator;
import org.digidoc4j.impl.bdoc.xades.SignatureExtender;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

/**
 * Offers functionality for handling data files and signatures in a container.
 */
public abstract class BDocContainer implements Container {

  private static final Logger logger = LoggerFactory.getLogger(BDocContainer.class);
  private Configuration configuration;
  private ValidationResult validationResult;

  /**
   * BDocContainer constructor. Instantiating BDoc container.
   */
  public BDocContainer() {
    logger.debug("Instantiating BDoc container");
    configuration = Configuration.getInstance();
  }

  /**
   * BDocContainer constructor. Instantiating BDoc container with configuration.
   *
   * @param configuration
   */
  public BDocContainer(Configuration configuration) {
    logger.debug("Instantiating BDoc container with configuration");
    this.configuration = configuration;
  }

  protected abstract ValidationResult validateContainer();

  protected abstract void writeAsicContainer(AsicContainerCreator zipCreator);

  @Override
  public String getType() {
    return "BDOC";
  }

  @Override
  public ValidationResult validate() {
    if (validationResult == null) {
      validationResult = validateContainer();
    }
    return validationResult;
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

  @Override
  public InputStream saveAsStream() {
    logger.debug("Saving container as stream");
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    save(outputStream);
    InputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    logger.info("Container was saved to stream");
    return inputStream;
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

  protected void validateIncomingSignature(Signature signature) {
    if (!(signature instanceof BDocSignature)) {
      throw new TechnicalException("BDoc signature must be an instance of BDocSignature");
    }
  }

  protected List<Signature> extendAllSignaturesProfile(SignatureProfile profile, List<Signature> signatures, List<DataFile> dataFiles) {
    logger.info("Extending all signatures' profile to " + profile.name());
    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    DSSDocument firstDetachedContent = detachedContentCreator.getFirstDetachedContent();
    List<DSSDocument> detachedContentList = detachedContentCreator.getDetachedContentList();
    SignatureExtender signatureExtender = new SignatureExtender(getConfiguration(), firstDetachedContent);
    List<DSSDocument> extendedSignatureDocuments = signatureExtender.extend(signatures, profile);
    List<Signature> extendedSignatures = parseSignatureFiles(extendedSignatureDocuments, detachedContentList);
    logger.debug("Finished extending all signatures");
    return extendedSignatures;
  }

  protected String createUserAgent() {
    if(!getSignatures().isEmpty()) {
      SignatureProfile profile = getSignatures().get(0).getProfile();
      return Helper.createBDocUserAgent(profile);
    }
    return Helper.createBDocUserAgent();
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

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
  }

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
