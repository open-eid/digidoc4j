/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.KeyInfo;
import ee.sk.digidoc.SignatureProductionPlace;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.SAXDigiDocFactory;
import ee.sk.utils.ConfigManager;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static ee.sk.digidoc.DataFile.CONTENT_EMBEDDED_BASE64;

/**
 * Offers functionality for handling data files and signatures in a container.
 * <p>
 * A container can contain several files and all those files can be signed using signing certificates.
 * A container can only be signed if it contains data files.
 * </p><p>
 * Data files can be added and removed from a container only if the container is not signed.
 * To modify the data list of a signed container by adding or removing datafiles you must first
 * remove all the signatures.
 * </p>
 */
public class DDocFacade implements SignatureFinalizer, Serializable {
  Logger logger = LoggerFactory.getLogger(DDocFacade.class);

  SignedDoc ddoc;
  private ArrayList<DigiDocException> openContainerExceptions = new ArrayList<>();
  private SignatureProfile signatureProfile = SignatureProfile.LT_TM;
  private SignatureParameters signatureParameters = new SignatureParameters();
  protected ee.sk.digidoc.Signature ddocSignature;
  private Configuration configuration;

  /**
   * Create a new container object of DDOC type Container.
   */
  public DDocFacade() {
    logger.debug("");
    intConfiguration();
    createDDOCContainer();
  }

  public SignedInfo prepareSigning(X509Certificate signerCert) {
    logger.info("Preparing signing");

    List<String> signerRoles = signatureParameters.getRoles();
    org.digidoc4j.SignatureProductionPlace signatureProductionPlace = signatureParameters.getProductionPlace();

    SignatureProductionPlace productionPlace = new SignatureProductionPlace(signatureProductionPlace.getCity(),
        signatureProductionPlace.getStateOrProvince(), signatureProductionPlace.getCountry(),
        signatureProductionPlace.getPostalCode());

    try {
      ddocSignature = ddoc.prepareSignature(signerCert, signerRoles.toArray(new String[signerRoles.size()]),
          productionPlace);

      String signatureId = signatureParameters.getSignatureId();
      if (signatureId != null) ddocSignature.setId(signatureId);

      return new SignedInfo(ddocSignature.calculateSignedInfoXML(), signatureParameters);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  public String getSignatureProfile() {
    String name = signatureProfile.name();
    logger.debug("Signature profile: " + name);
    return name;
  }

  public void setSignatureParameters(SignatureParameters signatureParameters) {
    logger.debug("");
    DigestAlgorithm algorithm = signatureParameters.getDigestAlgorithm();
    if (algorithm == null) {
      signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
    } else if (algorithm != DigestAlgorithm.SHA1) {
      NotSupportedException exception = new NotSupportedException("DDOC 1.3 supports only SHA1 as digest "
          + "algorithm. Specified algorithm is " + algorithm);
      logger.error(exception.toString());
      throw exception;
    }
    addSignatureProfile(signatureParameters);
    this.signatureParameters = signatureParameters.copy();
  }

  private void addSignatureProfile(SignatureParameters signatureParameters) {
    if(signatureParameters.getSignatureProfile() != null) {
      setSignatureProfile(signatureParameters.getSignatureProfile());
    }
  }

  public DigestAlgorithm getDigestAlgorithm() {
    DigestAlgorithm digestAlgorithm = signatureParameters.getDigestAlgorithm();
    logger.debug("Digest algorithm: " + digestAlgorithm);
    return digestAlgorithm;
  }

  /**
   * Create a new container object of DDOC type from a file
   *
   * @param path file path
   */
  public DDocFacade(String path) {
    this(path, new Configuration());
  }

  private void createDDOCContainer() {
    logger.debug("");
    try {
      ddoc = new SignedDoc("DIGIDOC-XML", "1.3");
      signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
      logger.info("DDoc container created");
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  /**
   * Create a new container object of DDOC type from a stream
   *
   * @param stream description
   */
  public DDocFacade(InputStream stream) {
    logger.debug("");
    intConfiguration();
    DigiDocFactory digFac = new SAXDigiDocFactory();
    try {
      ddoc = digFac.readDigiDocFromStream(stream);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
    logger.info("DDoc container opened from stream");
  }

  public DDocFacade(InputStream stream, Configuration configuration) {
    logger.debug("");
    this.configuration = configuration;
    ConfigManager.init(configuration.getJDigiDocConfiguration());
    ConfigManager.addProvider();
    DigiDocFactory digFac = new SAXDigiDocFactory();
    try {
        ddoc = digFac.readDigiDocFromStream(stream);
    } catch (DigiDocException e) {
        logger.error(e.getMessage());
        throw new DigiDoc4JException(e);
    }
    logger.info("DDoc container opened from stream");
  }

  /**
   * Create a new container object of DDOC type using specified configuration settings
   *
   * @param configuration configuration to use
   */
  public DDocFacade(Configuration configuration) {
    logger.debug("");
    this.configuration = configuration;
    ConfigManager.init(configuration.getJDigiDocConfiguration());
    ConfigManager.addProvider();
    createDDOCContainer();
  }

  private void intConfiguration() {
    logger.debug("");
    configuration = new Configuration();
    ConfigManager.init(configuration.getJDigiDocConfiguration());
    ConfigManager.addProvider();
  }

  /**
   * Create a new container object of DDOC type from a file using specified configuration settings
   *
   * @param fileName      container file name with path
   * @param configuration configuration to use
   */
  public DDocFacade(String fileName, Configuration configuration) {
    logger.info("Opening DDoc container from file: " + fileName);

    this.configuration = configuration;
    ConfigManager.init(configuration.getJDigiDocConfiguration());
    ConfigManager.addProvider();

    DigiDocFactory digFac = new SAXDigiDocFactory();
    try {
      ddoc = digFac.readSignedDocOfType(fileName, false, openContainerExceptions);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
    if (SignedDoc.hasFatalErrs(openContainerExceptions)) {
      DigiDocException fatalError = getFatalError();
      logger.error("Container has a fatal error: " + fatalError.getMessage());
      throw new DigiDoc4JException(fatalError);
    }
  }

  private DigiDocException getFatalError() {
    logger.debug("");
    DigiDocException exception = null;
    for (DigiDocException openContainerException : openContainerExceptions) {
      if (openContainerException.getCode() == DigiDocException.ERR_PARSE_XML) {
        exception = openContainerException;
      }
    }
    return exception;
  }

  DDocFacade(SignedDoc ddoc) {
    logger.debug("");
    intConfiguration();
    this.ddoc = ddoc;
  }

  public DataFile addDataFile(String path, String mimeType) {
    logger.info("Adding data file: " + path + ", mime type " + mimeType);
    try {
      ddoc.addDataFile(new File(path), mimeType, CONTENT_EMBEDDED_BASE64);
      return new DataFile(path, mimeType);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    logger.info("Adding data file: " + fileName + ", mime type: " + mimeType);
    try {
      ee.sk.digidoc.DataFile dataFile = new ee.sk.digidoc.DataFile(ddoc.getNewDataFileId(),
          ee.sk.digidoc.DataFile.CONTENT_EMBEDDED_BASE64,
          fileName, mimeType, ddoc);
      dataFile.setBodyFromStream(is);
      ddoc.addDataFile(dataFile);
      return new DataFile(is, fileName, mimeType);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  public void addDataFile(DataFile dataFile) {
    addDataFile(dataFile.getStream(), dataFile.getName(), dataFile.getMediaType());
  }

  public void addRawSignature(byte[] signatureBytes) {
    logger.debug("");
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(signatureBytes);
    addRawSignature(byteArrayInputStream);
    IOUtils.closeQuietly(byteArrayInputStream);
  }

  public void addRawSignature(InputStream signatureStream) {
    logger.info("Adding raw XAdES signature");
    try {
      ddoc.readSignature(signatureStream);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  public List<DataFile> getDataFiles() {
    logger.debug("");
    List<DataFile> dataFiles = new ArrayList<>();
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    if (ddocDataFiles == null) return dataFiles;
    for (Object ddocDataFile : ddocDataFiles) {
      ee.sk.digidoc.DataFile dataFile = (ee.sk.digidoc.DataFile) ddocDataFile;
      try {
        if (dataFile.getBody() == null) {
          DataFile dataFile1 = new DataFile(dataFile.getFileName(), dataFile.getMimeType());
          dataFile1.setId(dataFile.getId());
          dataFiles.add(dataFile1);
        } else {
          DataFile dataFile1 = new DataFile(dataFile.getBodyAsData(), dataFile.getFileName(), dataFile.getMimeType());
          dataFile1.setId(dataFile.getId());
          dataFiles.add(dataFile1);
        }
      } catch (DigiDocException e) {
        logger.error(e.getMessage());
        throw new DigiDoc4JException(e.getNestedException());
      }
    }
    return dataFiles;
  }

  /**
   * @deprecated will be removed in the future.
   */
  @Deprecated
  public DataFile getDataFile(int index) {
    logger.debug("Get data file for index " + index);
    return getDataFiles().get(index);
  }

  public int countDataFiles() {
    logger.debug("Get the number of data files");
    List<DataFile> dataFiles  = getDataFiles();

    return (dataFiles == null) ? 0 : dataFiles.size();
  }

  public void removeDataFile(String fileName) {
    logger.debug("File name: " + fileName);
    removeDataFile(new File(fileName));
  }

  private void removeDataFile(File file) {
    logger.info("Removing data file: " + file.getName());
    int index = -1;
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    for (int i = 0; i < ddocDataFiles.size(); i++) {
      ee.sk.digidoc.DataFile dataFile = (ee.sk.digidoc.DataFile) ddocDataFiles.get(i);
      if (dataFile.getFileName().equalsIgnoreCase(file.getName())) index = i;
    }
    if (index == -1) {
      DigiDoc4JException exception = new DigiDoc4JException("File not found");
      logger.error(exception.toString());
      throw exception;
    }

    try {
      ddoc.removeDataFile(index);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  /**
   * @deprecated will be removed in the future.
   */
  public void removeSignature(int index) {
    logger.info("Removing signature index: " + index);
    try {
      ddoc.removeSignature(index);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  public void save(String path) {
    logger.info("Saving container to path: " + path);
    try {
      ddoc.writeToFile(new File(path));
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  public void save(OutputStream out) {
    logger.info("Saving container to stream");
    try {
      ddoc.writeToStream(out);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  public Signature sign(SignatureToken signer) {
    logger.info("Signing DDoc container");
    calculateSignature(signer);
    try {
      signRaw(signer.sign(getDigestAlgorithm(), ddocSignature.calculateSignedInfoXML()));
      if (signatureProfile == SignatureProfile.LT_TM) {
        ddocSignature.getConfirmation();
      }
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }

    return new DDocSignature(ddocSignature);
  }

  public Signature signRaw(byte[] rawSignature) {
    logger.info("Finalizing DDoc signature");
    try {
      ddocSignature.setSignatureValue(rawSignature);
      DDocSignature signature = new DDocSignature(ddocSignature);
      signature.setIndexInArray(getSignatureIndexInArray());
      logger.info("Signing DDoc successfully completed");
      return signature;
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  private int getSignatureIndexInArray() {
    return ddoc.getSignatures().size() - 1;
  }

  public List<Signature> getSignatures() {
    logger.debug("");
    List<Signature> signatures = new ArrayList<>();

    ArrayList dDocSignatures = ddoc.getSignatures();

    if (dDocSignatures == null) {
      return signatures;
    }

    int signatureIndexInArray = 0;
    for (Object signature : dDocSignatures) {
      DDocSignature finalSignature = mapJDigiDocSignatureToDigiDoc4J((ee.sk.digidoc.Signature) signature);
      if (finalSignature != null) {
        finalSignature.setIndexInArray(signatureIndexInArray);
        signatures.add(finalSignature);
        signatureIndexInArray++;
      }
    }
    return signatures;
  }

  /**
   * @deprecated will be removed in the future.
   */
  public Signature getSignature(int index) {
    logger.debug("Get signature for index " + index);
    return getSignatures().get(index);
  }

  public int countSignatures() {
    logger.debug("Get the number of signatures");
    List<Signature> signatures = getSignatures();

    return (signatures == null) ? 0 : signatures.size();
  }

  private DDocSignature mapJDigiDocSignatureToDigiDoc4J(ee.sk.digidoc.Signature signature) {
    logger.debug("");
    DDocSignature finalSignature = new DDocSignature(signature);

    KeyInfo keyInfo = signature.getKeyInfo();
    if (keyInfo == null) {
      return null;
    }
    X509Certificate signersCertificate = keyInfo.getSignersCertificate();
    finalSignature.setCertificate(new X509Cert(signersCertificate));

    return finalSignature;
  }

  public Container.DocumentType getDocumentType() {
    logger.debug("");
    return Container.DocumentType.DDOC;
  }

  @SuppressWarnings("unchecked")
  public ValidationResult validate() {
    logger.info("Validating DDoc container");

    ArrayList exceptions = ddoc.verify(true, true);

    ArrayList containerExceptions = ddoc.validate(true);
    containerExceptions.addAll(openContainerExceptions);
    ValidationResultForDDoc result = new ValidationResultForDDoc(exceptions, containerExceptions);
    logger.info("DDoc container is valid: " + result.isValid());
    return result;
  }

  ee.sk.digidoc.Signature calculateSignature(SignatureToken signer) {
    logger.debug("");
    prepareSigning(signer.getCertificate());
    return ddocSignature;
  }

  private void addConfirmation() {
    logger.debug("");
    for (Object signature : ddoc.getSignatures()) {
      try {
        ((ee.sk.digidoc.Signature) signature).getConfirmation();
      } catch (DigiDocException e) {
        logger.error(e.getMessage());
        throw new DigiDoc4JException(e.getNestedException());
      }
    }
  }

  public String getVersion() {
    String version = ddoc.getVersion();
    logger.debug("Version: " + version);
    return version;
  }

  public void extendTo(SignatureProfile profile) {
    logger.info("Extending signature profile to " + profile.name());
    if (profile != SignatureProfile.LT_TM) {
      String errorMessage = profile + " profile is not supported for DDOC extension";
      logger.error(errorMessage);
      throw new NotSupportedException(errorMessage);
    }
    addConfirmation();
  }

  public void setSignatureProfile(SignatureProfile profile) {
    logger.debug("Adding signature profile " + profile);
    if (profile != SignatureProfile.LT_TM && profile != SignatureProfile.B_BES) {
      String errorMessage = profile + " profile is not supported for DDOC";
      logger.error(errorMessage);
      throw new NotSupportedException(errorMessage);
    }
    signatureProfile = profile;
  }

  /**
   * Returns ddoc format
   *
   * @return format as string
   */
  public String getFormat() {
    String format = ddoc.getFormat();
    logger.debug(format);
    return format;
  }

  public Configuration getConfiguration() {
    return configuration;
  }

  @Override
  public Signature finalizeSignature(byte[] signatureValue) {
    return signRaw(signatureValue);
  }
}
