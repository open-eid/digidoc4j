package org.digidoc4j.impl.bdoc.asic;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.DataFile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * Created by Andrei on 24.11.2017.
 */
public class TimeStampTokenValidator {

  private static final Logger logger = LoggerFactory.getLogger(TimeStampTokenValidator.class);

  private AsicParseResult containerParseResult;

  /**
   * Create TimeStampTokenValidator container
   *
   * @param containerParseResult
   */
  public TimeStampTokenValidator(AsicParseResult containerParseResult){
    this.containerParseResult = containerParseResult;
  }

  /**
   * Validate timestamp token
   *
   * @return ValidationResult
   */
  public ValidationResult validate() {
    logger.debug("Validating container");
    validateContainer(containerParseResult);
    TimeStampToken timeStampToken = getTimeStamp(containerParseResult);
    List<DigiDoc4JException> errors = validateTimeStamp(containerParseResult.getDataFiles().get(0), timeStampToken);
    Date signedTime = timeStampToken.getTimeStampInfo().getGenTime();
    String signedBy = getTimeStampTokenSigner(timeStampToken);

    TimeStampValidationResult timeStampValidationResult = generateTimeStampValidationResult(signedTime, signedBy, errors, timeStampToken);
    logger.info("Is container valid: " + timeStampValidationResult.isValid());
    return timeStampValidationResult;
  }

  private TimeStampValidationResult generateTimeStampValidationResult(Date signedTime, String signedBy, List<DigiDoc4JException> errors, TimeStampToken timeStampToken) {
    TimeStampValidationResult timeStampValidationResult = new TimeStampValidationResult();
    timeStampValidationResult.setErrors(errors);
    timeStampValidationResult.setSignedBy(signedBy);
    timeStampValidationResult.setSignedTime(DateUtils.getDateFormatterWithGMTZone().format(signedTime));
    timeStampValidationResult.setTimeStampToken(timeStampToken);
    return timeStampValidationResult;
  }

  private String getTimeStampTokenSigner(TimeStampToken timeStampToken) {
    GeneralName tsa = timeStampToken.getTimeStampInfo().getTsa();
    if (tsa == null) {
      return null;
    }
    ASN1Encodable x500Name = tsa.getName();
    if (x500Name instanceof X500Name) {
      return IETFUtils.valueToString(((X500Name) x500Name).getRDNs(BCStyle.CN)[0].getFirst().getValue());
    }
    return null;
  }

  private List<DigiDoc4JException> validateTimeStamp(DataFile datafile, TimeStampToken timeStampToken) {
    List<DigiDoc4JException> errors = new ArrayList<>();
    boolean isSignatureValid = isSignatureValid(timeStampToken);
    if (!isSignatureValid) {
      errors.add(new DigiDoc4JException("Signature not intact"));
    }

    byte[] dataFileBytes = datafile.getBytes();
    boolean isMessageImprintsValid = isMessageImprintsValid(dataFileBytes, timeStampToken);
    if (isSignatureValid && !isMessageImprintsValid) {
      errors.add(new DigiDoc4JException("Signature not intact"));
    }
    boolean isVersionValid = isVersionValid(timeStampToken);
    if (!isVersionValid) {
      errors.add(new DigiDoc4JException("TST version not supported"));
    }
    return errors;
  }

  private boolean isMessageImprintsValid(byte[] dataFileBytes, TimeStampToken timeStampToken) {
    final byte[] digestValue = DSSUtils.digest(DigestAlgorithm.SHA256, dataFileBytes);
    byte[] messageImprintDigest = timeStampToken.getTimeStampInfo().getMessageImprintDigest();
    return Arrays.equals(messageImprintDigest, digestValue);
  }

  private boolean isVersionValid(TimeStampToken timeStampToken) {
    return timeStampToken.getTimeStampInfo().toASN1Structure().getVersion().getValue().longValue() == 1;
  }

  private boolean isSignatureValid(TimeStampToken timeStampToken) {
    try {
      JcaSimpleSignerInfoVerifierBuilder sigVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
      Collection certCollection = timeStampToken.getCertificates().getMatches(timeStampToken.getSID());
      Iterator certIt = certCollection.iterator();
      X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
      Certificate x509Cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert.getEncoded()));

      SignerInformationVerifier signerInfoVerifier = sigVerifierBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(x509Cert.getPublicKey());
      return timeStampToken.isSignatureValid(signerInfoVerifier);
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    }
  }

  private void validateContainer(AsicParseResult documents) {
    long dataFileCount =  documents.getDataFiles() != null ? documents.getDataFiles().size() : 0L;
    long signatureFileCount = documents.getSignatures() != null ? documents.getSignatures().size() : 0L;

    if (dataFileCount != 1 || signatureFileCount > 0) {
      throw new DigiDoc4JException("Document does not meet the requirements: signatureFileCount = " + signatureFileCount
          + " (expected 0) , dataFileCount = " + dataFileCount + " (expected 1)");
    }
  }

  private TimeStampToken getTimeStamp(AsicParseResult documents) {
    try {
      CMSSignedData cms = new CMSSignedData(documents.getTimeStampToken().getBytes());
      return new TimeStampToken(cms);
    } catch (CMSException | TSPException | IOException e) {
      throw new DigiDoc4JException("Document malformed or not matching documentType : " + e.getMessage());
    }
  }
}
