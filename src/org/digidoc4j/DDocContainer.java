package org.digidoc4j;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignatureProductionPlace;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.SAXDigiDocFactory;
import ee.sk.utils.ConfigManager;
import org.digidoc4j.api.DataFile;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.Signer;
import org.digidoc4j.api.X509Cert;
import org.digidoc4j.api.exceptions.DigiDoc4JException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
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
public class DDocContainer implements ContainerInterface {

  private SignedDoc ddoc;

  /**
   * Create a new container object of DDOC type Container.
   */
  public DDocContainer() {
    ConfigManager.init("jdigidoc.cfg");
    try {
      ddoc = new SignedDoc("DIGIDOC-XML", "1.3");
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * Opens the container from a file.
   *
   * @param fileName container file name with path
   *                 ]
   */
  public DDocContainer(String fileName) {
    ConfigManager.init("jdigidoc.cfg");
    DigiDocFactory digFac = new SAXDigiDocFactory();
    try {
      ddoc = digFac.readSignedDoc(fileName);
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void addDataFile(String path, String mimeType) {
    try {
      ddoc.addDataFile(new File(path), mimeType, CONTENT_EMBEDDED_BASE64);
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void addDataFile(InputStream is, String fileName, String mimeType) {
    try {
      ee.sk.digidoc.DataFile dataFile = new ee.sk.digidoc.DataFile(ddoc.getNewDataFileId(),
          ee.sk.digidoc.DataFile.CONTENT_EMBEDDED_BASE64,
          fileName, mimeType, ddoc);
      dataFile.setBodyFromStream(is);
      ddoc.addDataFile(dataFile);
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void addRawSignature(byte[] signatureBytes) {
    addRawSignature(new ByteArrayInputStream(signatureBytes));
  }

  @Override
  public void addRawSignature(InputStream signatureStream) {
    try {
      ddoc.readSignature(signatureStream);
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public List<DataFile> getDataFiles() {
    List<DataFile> dataFiles = new ArrayList<DataFile>();
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    for (Object ddocDataFile : ddocDataFiles) {
      ee.sk.digidoc.DataFile dataFile = (ee.sk.digidoc.DataFile) ddocDataFile;
      try {
        if (dataFile.getBody() == null)
          dataFiles.add(new DataFile(dataFile.getFileName(), dataFile.getMimeType()));
        else
          dataFiles.add(new DataFile(dataFile.getBody(), dataFile.getFileName(), dataFile.getMimeType()));
      } catch (DigiDocException e) {
        throw new DigiDoc4JException(e);
      }
    }
    return dataFiles;
  }

  @Override
  public void removeDataFile(String fileName) {
    removeDataFile(new File(fileName));
  }

  private void removeDataFile(File file) {
    int index = -1;
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    for (int i = 0; i < ddocDataFiles.size(); i++) {
      ee.sk.digidoc.DataFile dataFile = (ee.sk.digidoc.DataFile) ddocDataFiles.get(i);
      if (dataFile.getFileName().equalsIgnoreCase(file.getName())) index = i;
    }
    if (index == -1) throw new DigiDoc4JException("File not found");

    try {
      ddoc.removeDataFile(index);
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void removeSignature(int index) {
    try {
      ddoc.removeSignature(index);
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void save(String path) {
    try {
      ddoc.writeToFile(new File(path));
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public Signature sign(Signer signer) {
    ee.sk.digidoc.Signature signature;
    try {
      List<String> signerRoles = signer.getSignerRoles();
      signature = ddoc.prepareSignature(signer.getCertificate().getX509Certificate(),
          signerRoles.toArray(new String[signerRoles.size()]),
          new SignatureProductionPlace(signer.getCity(), signer.getStateOrProvince(),
              signer.getCountry(), signer.getPostalCode()));

      signature.setSignatureValue(signer.sign(eu.europa.ec.markt.dss.DigestAlgorithm.SHA1.getXmlId(), signature.calculateSignedInfoXML()));

      signature.getConfirmation();
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }

    return new Signature(signature);
  }

  @Override
  public List<Signature> getSignatures() {
    List<Signature> signatures = new ArrayList<Signature>();
    ArrayList dDocSignatures = ddoc.getSignatures();

    for (Object signature : dDocSignatures) {
      Signature finalSignature = mapJDigiDocSignatureToDigidoc4J((ee.sk.digidoc.Signature) signature);
      signatures.add(finalSignature);
    }

    return signatures;
  }

  private Signature mapJDigiDocSignatureToDigidoc4J(ee.sk.digidoc.Signature signature) {
    Signature finalSignature = new Signature(signature);
    finalSignature.setCertificate(new X509Cert(signature.getLastCertValue().getCert())); //TODO can be several certs
    //TODO check logic about one role versus several roles
    return finalSignature;
  }

  @Override
  public DocumentType getDocumentType() {
    return DocumentType.DDOC;
  }

  @Override
  public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {

  }
}






