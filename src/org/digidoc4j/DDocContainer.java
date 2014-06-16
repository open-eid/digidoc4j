package org.digidoc4j;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignatureProductionPlace;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.Pkcs12SignatureFactory;
import ee.sk.digidoc.factory.SAXDigiDocFactory;
import ee.sk.utils.ConfigManager;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.SignerInformation;

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
    }
    catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public List<DataFile> getDataFiles() {
    List<DataFile> dataFiles = new ArrayList<DataFile>();
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    for (int i = 0; i < ddocDataFiles.size(); i++) {
      ee.sk.digidoc.DataFile dataFile = (ee.sk.digidoc.DataFile)ddocDataFiles.get(i);
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
      ee.sk.digidoc.DataFile dataFile = (ee.sk.digidoc.DataFile)ddocDataFiles.get(i);
      if (dataFile.getFileName().equalsIgnoreCase(file.getAbsolutePath())) index = i;
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
    }
    catch (DigiDocException e) {
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

      Pkcs12SignatureFactory sf = new Pkcs12SignatureFactory();
      sf.load("signout.p12", "PKCS12", "test");
      signature.setSignatureValue(sf.sign(signature.calculateSignedInfoXML(), 0, "test", signature));
      signature.getConfirmation();
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e);
    }

    Signature finalSignature = new Signature(signature.getSignatureValue().getValue(), signer);
    finalSignature.setSigningTime(signature.getSignatureProducedAtTime());
    finalSignature.setJDigiDocOrigin(signature);

    return finalSignature;
  }

  @Override
  public List<Signature> getSignatures() {
    List<Signature> signatures = new ArrayList<Signature>();
    ArrayList dDocSignatures = ddoc.getSignatures();

    for (Object signature : dDocSignatures) {
      Signature finalSignature = mapJDigiDocSignatureToDigidoc4J((ee.sk.digidoc.Signature)signature);
      signatures.add(finalSignature);
    }

    return signatures;
  }

  private Signature mapJDigiDocSignatureToDigidoc4J(ee.sk.digidoc.Signature signature) {
    Signature finalSignature = new Signature(signature.getSignatureValue().getValue());
    finalSignature.setCertificate(new X509Cert(signature.getLastCertValue().getCert())); //TODO can be several certs
    finalSignature.setSigningTime(signature.getSignatureProducedAtTime());
    finalSignature.setSignerRoles(getRolesFromSignedProperties(signature));
    finalSignature.setSignerInformation(
      new SignerInformation(signature.getSignedProperties().getSignatureProductionPlace().getCity(),
                            signature.getSignedProperties().getSignatureProductionPlace().getStateOrProvince(),
                            signature.getSignedProperties().getSignatureProductionPlace().getPostalCode(),
                            signature.getSignedProperties().getSignatureProductionPlace().getCountryName(), ""));
    finalSignature.setJDigiDocOrigin(signature);
    //TODO check logic about one role versus several roles
    return finalSignature;
  }

  private List<String> getRolesFromSignedProperties(ee.sk.digidoc.Signature signature) {
    List<String> roles = new ArrayList<String>();
    int numberOfRoles = signature.getSignedProperties().countClaimedRoles();
    for (int i = 0; i < numberOfRoles; i++) {
      roles.add(signature.getSignedProperties().getClaimedRole(i));
    }
    return roles;
  }

  @Override public DocumentType getDocumentType() {
    return DocumentType.DDOC;
  }
}






