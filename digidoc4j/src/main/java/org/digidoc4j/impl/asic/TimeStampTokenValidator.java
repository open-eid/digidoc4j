package org.digidoc4j.impl.asic;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * Created by Andrei on 24.11.2017.
 */
public class TimeStampTokenValidator {

  private final Logger log = LoggerFactory.getLogger(TimeStampTokenValidator.class);
  private AsicParseResult containerParseResult;

  /**
   * Create TimeStampTokenValidator container
   *
   * @param containerParseResult
   */
  public TimeStampTokenValidator(AsicParseResult containerParseResult) {
    this.containerParseResult = containerParseResult;
  }

  /**
   * Validate timestamp token
   *
   * @return ContainerValidationResult
   */
  public ContainerValidationResult validate() {
    this.log.debug("Validating container ...");
    this.validateContainer(this.containerParseResult);
    TimeStampToken token = this.getTimeStamp(this.containerParseResult);
    TimeStampContainerValidationResult result = generateTimeStampValidationResult(
        token.getTimeStampInfo().getGenTime(), this.getTimeStampTokenSigner(token),
        this.validateTimeStamp(this.containerParseResult.getDataFiles().get(0), token), token);
    return result;
  }

  /*
   * RESTRICTED METHODS
   */

  private TimeStampContainerValidationResult generateTimeStampValidationResult(Date signedTime, String signedBy,
                                                                               List<DigiDoc4JException> errors,
                                                                               TimeStampToken timeStampToken) {
    TimeStampContainerValidationResult result = new TimeStampContainerValidationResult();
    result.setErrors(errors);
    result.setSignedBy(signedBy);
    result.setSignedTime(DateUtils.getDateFormatterWithGMTZone().format(signedTime));
    result.setTimeStampToken(timeStampToken);
    return result;
  }

  private String getTimeStampTokenSigner(TimeStampToken token) {
    GeneralName tsa = token.getTimeStampInfo().getTsa();
    if (tsa == null) {
      return null;
    }
    ASN1Encodable encodable = tsa.getName();
    if (encodable instanceof X500Name) {
      return IETFUtils.valueToString(((X500Name) encodable).getRDNs(BCStyle.CN)[0].getFirst().getValue());
    }
    return null;
  }

  private List<DigiDoc4JException> validateTimeStamp(DataFile dataFile, TimeStampToken token) {
    List<DigiDoc4JException> errors = new ArrayList<>();
    boolean isSignatureValid = this.isSignatureValid(token);
    if (!isSignatureValid) {
      errors.add(new DigiDoc4JException("Signature not intact"));
    }
    boolean isMessageImprintsValid = this.isMessageImprintsValid(dataFile.getBytes(), token);
    if (isSignatureValid && !isMessageImprintsValid) {
      errors.add(new DigiDoc4JException("Signature not intact"));
    }
    boolean isVersionValid = this.isVersionValid(token);
    if (!isVersionValid) {
      errors.add(new DigiDoc4JException("TST version not supported"));
    }
    return errors;
  }

  private boolean isMessageImprintsValid(byte[] dataFileBytes, TimeStampToken token) {
    return Arrays.equals(token.getTimeStampInfo().getMessageImprintDigest(),
        DSSUtils.digest(DigestAlgorithm.SHA256, dataFileBytes));
  }

  private boolean isVersionValid(TimeStampToken token) {
    return token.getTimeStampInfo().toASN1Structure().getVersion().getValue().longValue() == 1;
  }

  private boolean isSignatureValid(TimeStampToken token) {
    try {
      X509CertificateHolder holder = (X509CertificateHolder) token.getCertificates().getMatches(token.getSID())
          .iterator().next();
      return token.isSignatureValid(
          new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
              DSSUtils.loadCertificate(holder.getEncoded()).getCertificate().getPublicKey()));
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    }
  }

  private void validateContainer(AsicParseResult documents) {
    long dataFileCount = documents.getDataFiles() != null ? documents.getDataFiles().size() : 0L;
    long signatureFileCount = documents.getSignatures() != null ? documents.getSignatures().size() : 0L;
    if (dataFileCount != 1 || signatureFileCount > 0) {
      throw new DigiDoc4JException("Document does not meet the requirements: signatureFileCount = " + signatureFileCount
          + " (expected 0) , dataFileCount = " + dataFileCount + " (expected 1)");
    }
  }

  private TimeStampToken getTimeStamp(AsicParseResult documents) {
    try {
      return new TimeStampToken(new CMSSignedData(documents.getTimeStampToken().getBytes()));
    } catch (CMSException | TSPException | IOException e) {
      throw new DigiDoc4JException("Document malformed or not matching documentType", e);
    }
  }

}
