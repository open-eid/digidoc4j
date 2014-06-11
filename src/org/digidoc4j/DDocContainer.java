package org.digidoc4j;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignatureProductionPlace;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.Pkcs12SignatureFactory;
import ee.sk.utils.ConfigManager;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;

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
   * @param path container file name with path
   * @throws Exception is thrown when the file was not found.
   */
  public DDocContainer(String path) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Adds a data file from the file system to the container.
   * <p>
   * Note:
   * Data files can be removed from a container only after all signatures have been removed.
   * </p>
   *
   * @param path     data file to be added to the container
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @throws Exception thrown if the data file path is incorrect or a data file with the same filename already exists.
   *                   Also, no data file can be added if the container already has one or more signatures.
   */
  public void addDataFile(String path, String mimeType) throws Exception {
    ddoc.addDataFile(new File(path), mimeType, CONTENT_EMBEDDED_BASE64);
  }

  /**
   * Adds a data file from the input stream (i.e. the date file content can be read from the internal memory buffer).
   * <p>
   * Note:
   * Data files can be added to a container only after all signatures have been removed.
   * </p>
   *
   * @param is       input stream from where data is read
   * @param fileName data file name in the container
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @throws Exception thrown if the data file path is incorrect or a data file with same file name already exists.
   *                   Also, no data file can be added if the container already has one or more signatures
   */
  public void addDataFile(InputStream is, String fileName, String mimeType)
    throws Exception {
    throw new NotYetImplementedException();
  }


  /**
   * Adds a signature to the container.
   *
   * @param signature signature to be added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  public void addRawSignature(byte[] signature) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Adds signature from the input stream to the container.
   *
   * @param signatureStream signature to be added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  public void addRawSignature(InputStream signatureStream) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Returns all data files in the container.
   *
   * @return list of all the data files in the container.
   */
  public List<DataFile> getDataFiles() {
    List<DataFile> dataFiles = new ArrayList<DataFile>();
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    for (int i = 0; i < ddocDataFiles.size(); i++) {
      ee.sk.digidoc.DataFile dataFile = (ee.sk.digidoc.DataFile)ddocDataFiles.get(i);
      dataFiles.add(new DataFile(dataFile.getFileName(), dataFile.getMimeType()));
    }
    return dataFiles;
  }


  /**
   * Removes a data file from the container by data file name. Any corresponding signatures will be deleted.
   *
   * @param fileName name of the data file to be removed
   */
  public void removeDataFile(String fileName) {
    int index = -1;
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    for (int i = 0; i < ddocDataFiles.size(); i++) {
      ee.sk.digidoc.DataFile dataFile = (ee.sk.digidoc.DataFile)ddocDataFiles.get(i);
      if (dataFile.getFileName().equalsIgnoreCase(fileName)) index = i;
    }
    if (index == -1) throw new DigiDoc4JException("File not found");

    try {
      ddoc.removeDataFile(index);
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * Removes the signature with the given signature id from the container.
   *
   * @param signatureId id of the signature to be removed
   * @throws Exception thrown if the signature id is incorrect
   */
  public void removeSignature(int signatureId) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Saves the container to the specified location.
   *
   * @param path file name and path.
   * @throws org.digidoc4j.exceptions.DigiDoc4JException
   *          thrown if there was a failure saving the BDOC container.
   *          For example if the added data file does not exist.
   */
  public void save(String path) throws DigiDoc4JException {
    if (ddoc == null)
      throw new NotYetImplementedException();
    try {
      ddoc.writeToFile(new File(path));
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * Signs all data files in the container.
   *
   * @param signer signer implementation
   * @return signature
   * @throws Exception thrown if signing the container failed
   */
  public Signature sign(Signer signer) throws Exception {
    ee.sk.digidoc.Signature signature;
    try {
      List<String> signerRoles = signer.getSignerRoles();
      signature = ddoc.prepareSignature(signer.getCertificate().getX509Certificate(),
                                        signerRoles.toArray(new String[signerRoles.size()]),
                                        new SignatureProductionPlace(signer.getCity(), signer.getStateOrProvince(),
                                                                     signer.getCountry(), signer.getPostalCode()));

      Pkcs12SignatureFactory sf = new Pkcs12SignatureFactory();
      sf.load("signout.p12", "PKCS12", "test");
      signature.setSignatureValue(sf.sign(signature.calculateSignedInfoDigest(), 0, "test", signature));
      signature.getConfirmation();
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e.getMessage());
    }

    Signature finalSignature = new Signature(signature.getSignatureValue().getValue(), signer);
    finalSignature.setSigningTime(signature.getSignatureProducedAtTime());

    return finalSignature;
  }

  /**
   * Returns a list of all signatures in the container.
   *
   * @return list of all signatures
   */
  public List<Signature> getSignatures() {
    throw new NotYetImplementedException();
  }
}






