package org.digidoc4j.api;

import org.apache.commons.io.FilenameUtils;
import org.digidoc4j.ASiCSContainer;
import org.digidoc4j.BDocContainer;
import org.digidoc4j.ContainerInterface;
import org.digidoc4j.DDocContainer;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.Helper;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

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
public class Container implements ContainerInterface {

  private ContainerInterface containerImplementation;

  /**
   * Creates Container specified by DocumentType
   *
   * @param documentType container type
   */
  public Container(DocumentType documentType) {
    if (documentType == DocumentType.ASIC_E)
      containerImplementation = new BDocContainer();
    else if (documentType == DocumentType.ASIC_S)
      containerImplementation = new ASiCSContainer();
    else
      containerImplementation = new DDocContainer();
  }

  /**
   * Create a new container object of ASIC_E type Container.
   */
  public Container() {
    containerImplementation = new BDocContainer();
  }


  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   */
  public Container(String path) {
    try {

      if (Helper.isZipFile(new File(path))) {
        if ("asics".equalsIgnoreCase(FilenameUtils.getExtension(path)))
          containerImplementation = new ASiCSContainer(path);
        else
          containerImplementation = new BDocContainer(path);
      } else {
        containerImplementation = new DDocContainer(path);
      }
    } catch (IOException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void addDataFile(String path, String mimeType) {
    containerImplementation.addDataFile(path, mimeType);
  }

  @Override
  public void addDataFile(InputStream is, String fileName, String mimeType) {
    containerImplementation.addDataFile(is, fileName, mimeType);
  }

  @Override
  public void addRawSignature(byte[] signature) {
    containerImplementation.addRawSignature(signature);
  }

  @Override
  public void addRawSignature(InputStream signatureStream) {
    containerImplementation.addRawSignature(signatureStream);
  }

  @Override
  public List<DataFile> getDataFiles() {
    return containerImplementation.getDataFiles();
  }

  @Override
  public void removeDataFile(String fileName) {
    containerImplementation.removeDataFile(fileName);
  }

  @Override
  public void removeSignature(int signatureId) {
    containerImplementation.removeSignature(signatureId);
  }

  @Override
  public void save(String path) throws DigiDoc4JException {
    containerImplementation.save(path);
  }

  @Override
  public Signature sign(Signer signer) {
    return containerImplementation.sign(signer);
  }

  @Override
  public List<Signature> getSignatures() {
    return containerImplementation.getSignatures();
  }

  @Override
  public DocumentType getDocumentType() {
    return containerImplementation.getDocumentType();
  }

  @Override
  public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    containerImplementation.setDigestAlgorithm(digestAlgorithm);
  }
}






