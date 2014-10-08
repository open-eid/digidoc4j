package org.digidoc4j.impl;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.KeyInfo;
import ee.sk.digidoc.SignatureProductionPlace;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.SAXDigiDocFactory;
import ee.sk.utils.ConfigManager;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
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
public class DDocContainer extends Container {
  Logger logger = LoggerFactory.getLogger(DDocContainer.class);

  SignedDoc ddoc;
  private ArrayList<DigiDocException> openContainerExceptions = new ArrayList<DigiDocException>();

  /**
   * Create a new container object of DDOC type Container.
   */
  public DDocContainer() {
    logger.debug("");
    intConfiguration();
    try {
      ddoc = new SignedDoc("DIGIDOC-XML", "1.3");
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  /**
   * description
   *
   * @param stream description
   */
  public DDocContainer(InputStream stream) {
    intConfiguration();
    DigiDocFactory digFac = new SAXDigiDocFactory();
    try {
      ddoc = digFac.readDigiDocFromStream(stream);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private void intConfiguration() {
    logger.debug("");
    Configuration configuration = new Configuration();
    ConfigManager.init(configuration.loadConfiguration("digidoc4j.yaml"));
    ConfigManager.addProvider();
  }

  /**
   * Opens the container from a file.
   *
   * @param fileName container file name with path
   */
  public DDocContainer(String fileName) {
    logger.debug("File name: " + fileName);

    intConfiguration();
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
    DigiDocException exception = null;
    for (DigiDocException openContainerException : openContainerExceptions) {
      if (openContainerException.getCode() == DigiDocException.ERR_PARSE_XML) {
        exception = openContainerException;
      }
    }
    return exception;
  }

  DDocContainer(SignedDoc ddoc) {
    logger.debug("");
    intConfiguration();
    this.ddoc = ddoc;
  }

  @Override
  public void addDataFile(String path, String mimeType) {
    logger.debug("Path: " + path + ", mime type " + mimeType);
    try {
      ddoc.addDataFile(new File(path), mimeType, CONTENT_EMBEDDED_BASE64);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  @Override
  public void addDataFile(InputStream is, String fileName, String mimeType) {
    logger.debug("File name: " + fileName + ", mime type: " + mimeType);
    try {
      ee.sk.digidoc.DataFile dataFile = new ee.sk.digidoc.DataFile(ddoc.getNewDataFileId(),
          ee.sk.digidoc.DataFile.CONTENT_EMBEDDED_BASE64,
          fileName, mimeType, ddoc);
      dataFile.setBodyFromStream(is);
      ddoc.addDataFile(dataFile);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void addRawSignature(byte[] signatureBytes) {
    logger.debug("");
    addRawSignature(new ByteArrayInputStream(signatureBytes));
  }

  @Override
  public void addRawSignature(InputStream signatureStream) {
    logger.debug("");
    try {
      ddoc.readSignature(signatureStream);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  @Override
  public List<DataFile> getDataFiles() {
    logger.debug("");
    List<DataFile> dataFiles = new ArrayList<DataFile>();
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    if (ddocDataFiles == null) return null;
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

  @Override
  public DataFile getDataFile(int index) {
    return getDataFiles().get(index);
  }

  @Override
  public void removeDataFile(String fileName) {
    logger.debug("File name: " + fileName);
    removeDataFile(new File(fileName));
  }

  private void removeDataFile(File file) {
    logger.debug("File name: " + file.getName());
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

  @Override
  public void removeSignature(int index) {
    logger.debug("Index: " + index);
    try {
      ddoc.removeSignature(index);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  @Override
  public void save(String path) {
    logger.debug("Path: " + path);
    try {
      ddoc.writeToFile(new File(path));
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  @Override
  public void save(OutputStream out) {
    logger.debug("Saves to " + out.getClass());
    try {
      ddoc.writeToStream(out);
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
  }

  @Override
  public Signature sign(Signer signer) {
    return sign(signer, null);
  }

  @Override
  public Signature sign(Signer signer, String signatureId) {
    logger.debug("");
    ee.sk.digidoc.Signature signature = calculateSignature(signer, signatureId);
    try {
      signature.getConfirmation();
    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }

    return new DDocSignature(signature);
  }

  @Override
  public void setConfiguration(Configuration conf) {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public List<Signature> getSignatures() {
    logger.debug("");
    List<Signature> signatures = new ArrayList<Signature>();

    ArrayList dDocSignatures = ddoc.getSignatures();

    if (dDocSignatures == null) {
      return null;
    }

    for (Object signature : dDocSignatures) {
      Signature finalSignature = mapJDigiDocSignatureToDigiDoc4J((ee.sk.digidoc.Signature) signature);
      if (finalSignature != null) {
        signatures.add(finalSignature);
      }
    }
    return signatures;
  }

  @Override
  public Signature getSignature(int index) {
    return getSignatures().get(index);
  }

  private Signature mapJDigiDocSignatureToDigiDoc4J(ee.sk.digidoc.Signature signature) {
    logger.debug("");
    Signature finalSignature = new DDocSignature(signature);

    KeyInfo keyInfo = signature.getKeyInfo();
    if (keyInfo == null) {
      return null;
    }
    X509Certificate signersCertificate = keyInfo.getSignersCertificate();
    finalSignature.setCertificate(new X509Cert(signersCertificate));

    return finalSignature;
  }

  @Override
  public DocumentType getDocumentType() {
    logger.debug("");
    return DocumentType.DDOC;
  }

  @Override
  public void setDigestAlgorithm(DigestAlgorithm algorithm) {
    logger.debug("");
  }


  @SuppressWarnings("unchecked")
  @Override
  public ValidationResult validate() {
    logger.debug("");

    ArrayList exceptions = ddoc.verify(true, true);

    ArrayList containerExceptions = ddoc.validate(true);
    containerExceptions.addAll(openContainerExceptions);
    return new ValidationResultForDDoc(exceptions, containerExceptions);
  }

  @Override
  public Signature signWithoutOCSP(Signer signer) {
    logger.debug("");
    return new DDocSignature(calculateSignature(signer, null));
  }

  @Override
  public Signature signWithoutOCSP(Signer signer, String signatureId) {
    logger.debug("");
    return new DDocSignature(calculateSignature(signer, signatureId));
  }

  ee.sk.digidoc.Signature calculateSignature(Signer signer, String signatureId) {
    ee.sk.digidoc.Signature signature;
    try {
      List<String> signerRoles = signer.getSignerRoles();
      SignatureProductionPlace productionPlace = new SignatureProductionPlace(signer.getCity(),
          signer.getStateOrProvince(), signer.getCountry(), signer.getPostalCode());

      signature = ddoc.prepareSignature(signer.getCertificate().getX509Certificate(),
          signerRoles.toArray(new String[signerRoles.size()]),
          productionPlace);

      if (signatureId != null)
        signature.setId(signatureId);

      signature.setSignatureValue(signer.sign(eu.europa.ec.markt.dss.DigestAlgorithm.SHA1.getXmlId(),
          signature.calculateSignedInfoXML()));

    } catch (DigiDocException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e.getNestedException());
    }
    return signature;
  }

  @Override
  public void addConfirmation() {
    for (Object signature : ddoc.getSignatures()) {
      try {
        ((ee.sk.digidoc.Signature) signature).getConfirmation();
      } catch (DigiDocException e) {
        logger.error(e.getMessage());
        throw new DigiDoc4JException(e.getNestedException());
      }
    }
  }

  @Override
  public String getVersion() {
    return ddoc.getVersion();
  }

  /**
   * Returns ddoc format
   *
   * @return format as string
   */
  public String getFormat() {
    return ddoc.getFormat();
  }
}
