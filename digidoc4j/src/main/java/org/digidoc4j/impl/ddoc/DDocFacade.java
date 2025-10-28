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

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FilenameUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.DigestDataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.X509Cert;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.digidoc4j.ddoc.DigiDocException.WARN_WEAK_DIGEST;

/**
 * Offers validation specific functionality of a DDOC container.
 */
public class DDocFacade implements Serializable {
  private static final Logger logger = LoggerFactory.getLogger(DDocFacade.class);

  private static final String HASHCODE_CONTENT_TYPE = "HASHCODE";
  private static final Instant TERA_SUPPORT_END = Instant.parse("2018-07-01T00:00:00Z");

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
      String dataFileName = FilenameUtils.getName(dataFile.getFileName());
      try {
        if (isHashcodeForm(dataFile)) {
            DigestDataFile digestDataFile = new DigestDataFile(dataFileName, DigestAlgorithm.SHA1, dataFile.getDigestValueOfType("sha1"), dataFile.getMimeType());
            digestDataFile.setContentType(HASHCODE_CONTENT_TYPE);
            dataFiles.add(digestDataFile);
        } else {
            if (dataFile.getBody() == null) {
                DataFile dataFile1 = new DataFile(dataFile.getFileName(), dataFile.getMimeType());
                dataFile1.setId(dataFile.getId());
                dataFiles.add(dataFile1);
            } else {
                DataFile dataFile1 = new DataFile(dataFile.getBodyAsData(), dataFileName, dataFile.getMimeType());
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

  /**
   * @deprecated Deprecated for removal. Use {@link #validate(Date)} instead.
   */
  @Deprecated
  public ContainerValidationResult validate() {
    return validate(new Date());
  }

  public ContainerValidationResult validate(Date validationTime) {
    logger.debug("Validating DDoc container ...");
    Map<String, ValidationResult> signatureResults = new LinkedHashMap<>();

    // The implementation of {@link SignedDoc#verify(boolean, boolean)} has been re-implemented here in order to get
    //  access to the verification results of individual signatures.
    @SuppressWarnings("unchecked")
    ArrayList<DigiDocException> containerExceptions = ddoc.validate(true);
    boolean noFatalErrors = !SignedDoc.hasFatalErrs(containerExceptions);
    ArrayList<DigiDocException> verificationExceptions = new ArrayList<>(containerExceptions);
    containerExceptions.addAll(openContainerExceptions);
    for (int i = 0; i < ddoc.countSignatures(); ++i) {
      org.digidoc4j.ddoc.Signature signature = ddoc.getSignature(i);
      List<DigiDocException> signatureExceptions = validateSignature(signature, verificationExceptions);
      String signatureId = signature.getId();
      if (signatureId == null) {
        logger.warn("DDoc signature is missing signature ID");
      } else if (signatureResults.containsKey(signatureId)) {
        logger.warn("DDoc signature ID collision detected, mapping '{}' to first matching result!", signatureId);
      } else {
        signatureResults.put(signatureId, new DDocSignatureValidationResult(signatureExceptions, ddoc.getFormat()));
      }
    }
    if (noFatalErrors && ddoc.countSignatures() == 0) {
      verificationExceptions.add(new DigiDocException(DigiDocException.ERR_NOT_SIGNED, "This document is not signed!", null));
    }

    DDocSignatureValidationResult result = new DDocContainerValidationResult(
            verificationExceptions,
            containerExceptions,
            signatureResults,
            ddoc.getFormat()
    );

    if (isSha1WarningRequired(validationTime)) {
      result.getContainerWarnings().add(new DigiDoc4JException(WARN_WEAK_DIGEST,
              "The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"
      ));
    }
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

  private List<DigiDocException> validateSignature(
          org.digidoc4j.ddoc.Signature signature,
          List<DigiDocException> verificationErrorAccumulator
  ) {
    try {
      @SuppressWarnings("unchecked")
      List<DigiDocException> verificationResult = signature.verify(ddoc, true, true);
      logger.debug("Verification of signature '{}' returned: {}", signature.getId(), verificationResult);
      if (CollectionUtils.isNotEmpty(verificationResult)) {
        verificationErrorAccumulator.addAll(verificationResult);
      }
      return verificationResult;
    } catch (Exception e) {
      logger.debug("Verification of signature '{}' failed", signature.getId(), e);

      @SuppressWarnings("unchecked")
      List<DigiDocException> validationResult = signature.validate();
      logger.debug("Validation of signature '{}' returned: {}", signature.getId(), validationResult);
      if (CollectionUtils.isNotEmpty(validationResult)) {
        return validationResult;
      }

      validationResult = new ArrayList<>();
      validationResult.add(new DigiDocException(DigiDocException.ERR_VERIFY, "Fatal error", null));
      logger.debug("Unverifiable signature '{}' has no validation errors; returning fatal error", signature.getId());
      return validationResult;
    }
  }

  private static boolean isSha1WarningRequired(Date validationTime) {
    return validationTime == null || validationTime.toInstant().isAfter(TERA_SUPPORT_END);
  }

}
