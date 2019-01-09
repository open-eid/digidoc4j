package org.digidoc4j.impl.pades;


import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.Configuration;
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
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * Created by Andrei on 17.11.2017.
 */
public class PadesContainer implements Container {

  public static final String PADES = "PADES";
  private final Configuration configuration;
  private final String containerPath;

  /**
   * @param configuration configuration context
   * @param containerPath the path of container
   */
  public PadesContainer(Configuration configuration, String containerPath) {
    this.configuration = configuration;
    this.containerPath = containerPath;
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
    return PADES;
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
   * Validate pades container
   *
   * @return ValidationResult
   */
  public ContainerValidationResult validate() {
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(new File
        (this.containerPath)));
    validator.setCertificateVerifier(new SKCommonCertificateVerifier());
    Reports reports = validator.validateDocument();
    PadesContainerValidationResult result = new PadesContainerValidationResult(reports.getSimpleReport());
    result.setReport(reports.getXmlSimpleReport());
    for (String id : reports.getSimpleReport().getSignatureIdList()) {
      Indication indication = reports.getSimpleReport().getIndication(id);
      if (!Indication.TOTAL_PASSED.equals(indication)) {
        result.getErrors().addAll(this.getExceptions(reports.getSimpleReport().getErrors(id)));
        result.getWarnings().addAll(this.getExceptions(reports.getSimpleReport().getWarnings(id)));
      }
    }
    result.print(this.configuration);
    return result;
  }

  @Override
  public void setTimeStampToken(DataFile timeStampToken) {
    throw new NotSupportedException("Not for Pades container");
  }

  @Override
  public DataFile getTimeStampToken() {
    throw new NotSupportedException("Not for Pades container");
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
}