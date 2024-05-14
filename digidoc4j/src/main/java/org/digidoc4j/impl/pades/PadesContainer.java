/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.pades;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.Timestamp;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.exceptions.UntrustedRevocationSourceException;
import org.digidoc4j.impl.AiaSourceFactory;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.digidoc4j.impl.asic.xades.validation.TimestampSignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Andrei on 17.11.2017.
 */
public class PadesContainer extends PdfBoxDefaultObjectFactory implements Container {

  private static final Logger logger = LoggerFactory.getLogger(PadesContainer.class);
  private static final String NOT_FOR_THIS_CONTAINER = "Not for PAdES container";

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
  public void extendSignatureProfile(SignatureProfile profile, List<Signature> signaturesToExtend) {
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
    FileDocument document = new FileDocument(new File(this.containerPath));
    if (!PAdESUtils.isPDFDocument(document)) {
      String message = "Invalid PDF document provided!";
      logger.error(message);
      throw new DigiDoc4JException(message);
    }
    SignedDocumentValidator validator = new PDFDocumentValidator(document);
    validator.setCertificateVerifier(createCertificateVerifier());
    Reports reports = validator.validateDocument(this.getClass().getClassLoader().getResourceAsStream(this.configuration.getValidationPolicy()));
    SimpleReport simpleReport = reports.getSimpleReport();
    PadesContainerValidationResult result = new PadesContainerValidationResult(simpleReport);
    result.setReport(reports.getXmlSimpleReport());
    for (String id : simpleReport.getSignatureIdList()) {
      Indication indication = simpleReport.getIndication(id);
      if (!Indication.TOTAL_PASSED.equals(indication)) {
        result.getErrors().addAll(getExceptionsFromMessages(simpleReport.getAdESValidationErrors(id)));
        result.getErrors().addAll(getExceptionsFromMessages(simpleReport.getQualificationErrors(id)));
        result.getWarnings().addAll(getExceptionsFromMessages(simpleReport.getAdESValidationWarnings(id)));
        result.getWarnings().addAll(getExceptionsFromMessages(simpleReport.getQualificationWarnings(id)));
        for (XmlTimestamp timestamp : simpleReport.getSignatureTimestamps(id)) {
          if (timestamp.getAdESValidationDetails() != null) {
            result.getErrors().addAll(getExceptionsFromXmlMessages(timestamp.getAdESValidationDetails().getError()));
            result.getWarnings().addAll(getExceptionsFromXmlMessages(timestamp.getAdESValidationDetails().getWarning()));
          }
          if (timestamp.getQualificationDetails() != null) {
            result.getErrors().addAll(getExceptionsFromXmlMessages(timestamp.getQualificationDetails().getError()));
            result.getWarnings().addAll(getExceptionsFromXmlMessages(timestamp.getQualificationDetails().getWarning()));
          }
        }
      }
    }
    addRevocationErrors(result, reports);
    result.print(this.configuration);
    return result;
  }


  /**
   * Copied from {@link TimestampSignatureValidator#addRevocationErrors()}
   * TODO: Refactor to avoid code duplications & add further error checking
   */
  private void addRevocationErrors(PadesContainerValidationResult result, Reports reports) {
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

  @Override
  public void addTimestamp(Timestamp timestamp) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public void removeTimestamp(Timestamp timestamp) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  @Deprecated
  public void setTimeStampToken(DataFile timeStampToken) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  @Deprecated
  public DataFile getTimeStampToken() {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  private static List<DigiDoc4JException> getExceptionsFromMessages(List<Message> exceptionMessages) {
    List<DigiDoc4JException> exceptions = new ArrayList<>();
    for (Message exceptionMessage : exceptionMessages) {
      exceptions.add(new DigiDoc4JException(exceptionMessage.getValue()));
    }
    return exceptions;
  }

  private static List<DigiDoc4JException> getExceptionsFromXmlMessages(List<XmlMessage> exceptionMessages) {
    List<DigiDoc4JException> exceptions = new ArrayList<>();
    for (XmlMessage exceptionMessage : exceptionMessages) {
      exceptions.add(new DigiDoc4JException(exceptionMessage.getValue()));
    }
    return exceptions;
  }

  @Override
  public Configuration getConfiguration() {
    return configuration;
  }

  @Override
  public void save(OutputStream out) {
    throw new NotYetImplementedException();
  }

  private CertificateVerifier createCertificateVerifier() {
    logger.debug("Creating new certificate verifier");
    CertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setCrlSource(null); //Disable CRL checks
    logger.debug("Setting trusted cert source to the certificate verifier");
    certificateVerifier.setTrustedCertSources(configuration.getTSL());
    logger.debug("Setting custom AIA source to the certificate verifier");
    certificateVerifier.setAIASource(new AiaSourceFactory(configuration).create());
    logger.debug("Finished creating certificate verifier");
    return certificateVerifier;
  }
}
