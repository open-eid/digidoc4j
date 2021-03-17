package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.exceptions.UntrustedRevocationSourceException;
import org.digidoc4j.impl.AiaDataLoaderFactory;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class AsicContainerWithCades implements Container {


  private static final Logger logger = LoggerFactory.getLogger(AsicContainerWithCades.class);

  public static final String TYPE = "Asic";
  private final Configuration configuration;
  private final DSSDocument dssDocument;

  /**
   * @param configuration configuration context
   * @param dssDocument   the dssDocument of container
   */
  public AsicContainerWithCades(Configuration configuration, DSSDocument dssDocument) {
    this.configuration = configuration;
    this.dssDocument = dssDocument;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    throw new NotYetImplementedException();
  }

  @Override
  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    throw new NotYetImplementedException();
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    throw new NotYetImplementedException();
  }

  @Override
  public void addDataFile(DataFile dataFile) {
    throw new NotYetImplementedException();
  }

  @Override
  public void addSignature(Signature signature) {
    throw new NotYetImplementedException();
  }

  @Override
  public List<DataFile> getDataFiles() {
    throw new NotYetImplementedException();
  }

  @Override
  public String getType() {
    return TYPE;
  }

  @Override
  public List<Signature> getSignatures() {
    throw new NotYetImplementedException();
  }

  @Override
  public void removeDataFile(DataFile file) {
    throw new NotYetImplementedException();
  }

  @Override
  public void removeSignature(Signature signature) {
    throw new NotYetImplementedException();
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    throw new NotYetImplementedException();
  }

  @Override
  public File saveAsFile(String filePath) {
    throw new NotYetImplementedException();
  }

  @Override
  public InputStream saveAsStream() {
    throw new NotYetImplementedException();
  }

  /**
   * Validate ASIC container with Cades
   *
   * @return ValidationResult
   */
  public ContainerValidationResult validate() {
    SignedDocumentValidator validator = new ASiCContainerWithCAdESValidator(dssDocument);
    if (!validator.isSupported(dssDocument)) {
      String message = "Invalid ASIC with Cades document provided!";
      logger.error(message);
      throw new DigiDoc4JException(message);
    }
    validator.setCertificateVerifier(createCertificateVerifier());
    Reports reports = validator.validateDocument(getValidationPolicyAsStream());
    AsicContainerWithCadesValidationResult result = new AsicContainerWithCadesValidationResult(reports.getSimpleReport());
    result.setReport(reports.getXmlSimpleReport());
    for (String id : reports.getSimpleReport().getSignatureIdList()) {
      Indication indication = reports.getSimpleReport().getIndication(id);
      if (!Indication.TOTAL_PASSED.equals(indication)) {
        result.getErrors().addAll(this.getExceptions(reports.getSimpleReport().getErrors(id)));
        result.getWarnings().addAll(this.getExceptions(reports.getSimpleReport().getWarnings(id)));
      }
    }
    addRevocationErrors(result, reports);
    result.print(this.configuration);
    return result;
  }

  private void addRevocationErrors(AsicContainerWithCadesValidationResult result, Reports reports) {
    DiagnosticData diagnosticData = reports.getDiagnosticData();
    if (diagnosticData == null) {
      return;
    }
    String signatureId = diagnosticData.getFirstSignatureId();
    String certificateId = diagnosticData.getSigningCertificateId(signatureId);
    if (certificateId == null) {
      return;
    }

    RevocationType certificateRevocationSource = diagnosticData.getCertificateRevocationSource(certificateId);
    logger.debug("Revocation source is <{}>", certificateRevocationSource);
    if (RevocationType.CRL.equals(certificateRevocationSource)) {
      logger.error("Signing certificate revocation source is CRL instead of OCSP");
      result.getErrors().add(new UntrustedRevocationSourceException());
    }

  }

  private InputStream getValidationPolicyAsStream() {
    String policyFile = this.configuration.getValidationPolicy();
    if (Files.exists(Paths.get(policyFile))) {
      try {
        return new FileInputStream(policyFile);
      } catch (FileNotFoundException ex) {
        logger.warn(ex.getMessage());
      }
    }
    return this.getClass().getClassLoader().getResourceAsStream(policyFile);
  }

  @Override
  public void setTimeStampToken(DataFile timeStampToken) {
    throw new NotYetImplementedException();
  }

  @Override
  public DataFile getTimeStampToken() {
    throw new NotYetImplementedException();
  }

  private List<DigiDoc4JException> getExceptions(List<String> exceptionString) {
    List<DigiDoc4JException> exc = new ArrayList<>();
    for (String s : exceptionString) {
      exc.add(new DigiDoc4JException(s));
    }
    return exc;
  }

  @Override
  public SignedInfo prepareSigning(X509Certificate signerCert) {
    throw new NotYetImplementedException();
  }

  @Override
  public Configuration getConfiguration() {
    return configuration;
  }

  @Override
  public String getSignatureProfile() {
    throw new NotYetImplementedException();
  }

  @Override
  public void setSignatureParameters(SignatureParameters signatureParameters) {
    throw new NotYetImplementedException();
  }

  @Override
  public DigestAlgorithm getDigestAlgorithm() {
    throw new NotYetImplementedException();
  }

  @Override
  public void addRawSignature(byte[] signature) {
    throw new NotYetImplementedException();
  }

  @Override
  public void addRawSignature(InputStream signatureStream) {
    throw new NotYetImplementedException();
  }

  @Override
  public DataFile getDataFile(int index) {
    throw new NotYetImplementedException();
  }

  @Override
  public int countDataFiles() {
    throw new NotYetImplementedException();
  }

  @Override
  public void removeDataFile(String fileName) {
    throw new NotYetImplementedException();
  }

  @Override
  public void removeSignature(int signatureId) {
    throw new NotYetImplementedException();
  }

  @Override
  public void save(String path) {
    throw new NotYetImplementedException();
  }

  @Override
  public void save(OutputStream out) {
    throw new NotYetImplementedException();
  }

  @Override
  public Signature sign(SignatureToken signatureToken) {
    throw new NotYetImplementedException();
  }

  @Override
  public Signature signRaw(byte[] rawSignature) {
    throw new NotYetImplementedException();
  }

  @Override
  public Signature getSignature(int index) {
    throw new NotYetImplementedException();
  }

  @Override
  public int countSignatures() {
    throw new NotYetImplementedException();
  }

  @Override
  public DocumentType getDocumentType() {
    throw new NotYetImplementedException();
  }

  @Override
  public String getVersion() {
    throw new NotYetImplementedException();
  }

  @Override
  public void extendTo(SignatureProfile profile) {
    throw new NotYetImplementedException();
  }

  @Override
  public void setSignatureProfile(SignatureProfile profile) {
    throw new NotYetImplementedException();
  }

  private CertificateVerifier createCertificateVerifier() {
    logger.debug("Creating new certificate verifier");
    CertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setCrlSource(null); //Disable CRL checks
    certificateVerifier.setSignatureCRLSource(null); //Disable CRL checks
    logger.debug("Setting trusted cert source to the certificate verifier");
    certificateVerifier.setTrustedCertSources(configuration.getTSL());
    logger.debug("Setting custom data loader to the certificate verifier");
    certificateVerifier.setDataLoader(new AiaDataLoaderFactory(configuration, Constant.USER_AGENT_STRING).create());
    logger.debug("Finished creating certificate verifier");
    return certificateVerifier;
  }
}