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

import org.digidoc4j.*;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.KeyInfo;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Offers validation specific functionality of a DDOC container.
 */
public class DDocFacade implements Serializable {
  private static final Logger logger = LoggerFactory.getLogger(DDocFacade.class);

  private static final String HASHCODE_CONTENT_TYPE = "HASHCODE";

  protected SignedDoc ddoc;
  private ArrayList<DigiDocException> openContainerExceptions = new ArrayList<>();
  private SignatureProfile signatureProfile = SignatureProfile.LT_TM;
  private Configuration configuration;
  static ConfigManagerInitializer configManagerInitializer = new ConfigManagerInitializer();

  /**
   * @param configuration configuration context
   */
  public DDocFacade(Configuration configuration) {
    this.configuration = configuration;
    this.initConfigManager();
  }

  DDocFacade(SignedDoc ddoc) {
    this.initilizeConfiguration();
    this.ddoc = ddoc;
  }

  public String getSignatureProfile() {
    String name = signatureProfile.name();
    logger.debug("Signature profile: " + name);
    return name;
  }

  public DigestAlgorithm getDigestAlgorithm() {
    return DigestAlgorithm.SHA1;
  }

  private void initilizeConfiguration() {
    this.configuration = Configuration.getInstance();
    this.initConfigManager();
  }

  public List<DataFile> getDataFiles() {
    List<DataFile> dataFiles = new ArrayList<>();
    ArrayList ddocDataFiles = ddoc.getDataFiles();
    if (ddocDataFiles == null) return dataFiles;
    for (Object ddocDataFile : ddocDataFiles) {
      org.digidoc4j.ddoc.DataFile dataFile = (org.digidoc4j.ddoc.DataFile) ddocDataFile;
      try {
        if (isHashcodeForm(dataFile)) {
            DigestDataFile digestDataFile = new DigestDataFile(dataFile.getFileName(), DigestAlgorithm.SHA1, dataFile.getDigestValueOfType("sha1"));
            digestDataFile.setContentType(HASHCODE_CONTENT_TYPE);
            dataFiles.add(digestDataFile);
        } else {
            if (dataFile.getBody() == null) {
                DataFile dataFile1 = new DataFile(dataFile.getFileName(), dataFile.getMimeType());
                dataFile1.setId(dataFile.getId());
                dataFiles.add(dataFile1);
            } else {
                DataFile dataFile1 = new DataFile(dataFile.getBodyAsData(), dataFile.getFileName(), dataFile.getMimeType());
                dataFile1.setId(dataFile.getId());
                dataFiles.add(dataFile1);
            }
        }
      } catch (DigiDocException e) {
        throw new DigiDoc4JException(e.getMessage(), e.getNestedException());
      }
    }
    return dataFiles;
  }

  private boolean isHashcodeForm(org.digidoc4j.ddoc.DataFile dataFile) {
    return HASHCODE_CONTENT_TYPE.equals(dataFile.getContentType());
  }

  public int countDataFiles() {
    logger.debug("Get the number of data files");
    List<DataFile> dataFiles = getDataFiles();
    return (dataFiles == null) ? 0 : dataFiles.size();
  }

  public void save(String path) {
    logger.info("Saving container to path: " + path);
    try {
      ddoc.writeToFile(new File(path));
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e.getMessage(), e.getNestedException());
    }
  }

  public void save(OutputStream out) {
    logger.info("Saving container to stream");
    try {
      ddoc.writeToStream(out);
    } catch (DigiDocException e) {
      throw new DigiDoc4JException(e.getMessage(), e.getNestedException());
    }
  }

  public List<Signature> getSignatures() {
    List<Signature> signatures = new ArrayList<>();
    ArrayList dDocSignatures = ddoc.getSignatures();
    if (dDocSignatures == null) {
      return signatures;
    }
    int signatureIndexInArray = 0;
    for (Object signature : dDocSignatures) {
      DDocSignature finalSignature = mapDDoc4JSignatureToDigiDoc4J((org.digidoc4j.ddoc.Signature) signature);
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

  private DDocSignature mapDDoc4JSignatureToDigiDoc4J(org.digidoc4j.ddoc.Signature signature) {
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
    return Container.DocumentType.DDOC;
  }

  public ContainerValidationResult validate() {
    logger.debug("Validating DDoc container ...");
    List containerExceptions = this.ddoc.validate(true);
    containerExceptions.addAll(this.openContainerExceptions);
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(this.ddoc.verify(true, true),
        containerExceptions, this.ddoc.getFormat());
    result.print(this.configuration);
    return result;
  }

  public String getVersion() {
    String version = ddoc.getVersion();
    logger.debug("Version: " + version);
    return version;
  }

  /**
   * Returns ddoc format
   *
   * @return format as string
   */
  public String getFormat() {
    return ddoc.getFormat();
  }

  public Configuration getConfiguration() {
    return configuration;
  }

  private void initConfigManager() {
    configManagerInitializer.initConfigManager(this.configuration);
  }

  protected void setSignedDoc(SignedDoc signedDoc) {
    ddoc = signedDoc;
  }

  protected void setContainerOpeningExceptions(ArrayList<DigiDocException> openContainerExceptions) {
    this.openContainerExceptions = openContainerExceptions;
  }

}
