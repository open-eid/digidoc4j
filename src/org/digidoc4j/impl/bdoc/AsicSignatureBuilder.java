/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_B;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LT;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LTA;
import static java.lang.Math.min;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.digidoc4j.impl.bdoc.ocsp.OcspSourceBuilder.anOcspSource;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.bdoc.asic.AsicSContainer;
import org.digidoc4j.impl.bdoc.asic.DetachedContentCreator;
import org.digidoc4j.impl.bdoc.ocsp.SKOnlineOCSPSource;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.impl.bdoc.xades.XadesSigningDssFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.signature.DSSSignatureUtils;

/**
 * Signature builder for Asic conteiner.
 */
public class AsicSignatureBuilder extends SignatureBuilder implements SignatureFinalizer {

  private static final Logger logger = LoggerFactory.getLogger(AsicSignatureBuilder.class);
  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
  private static final int hexMaxlen = 10;
  private static final int maxTryCount = 5;
  protected transient XadesSigningDssFacade facade;
  private Date signingDate;

  /**
   * Checks if the signature is ASN.1 encoded.
   *
   * @param signatureValue signature value to check.
   * @return if the signature is ASN.1 encoded.
   */
  private static boolean isAsn1Encoded(byte[] signatureValue) {
    ASN1InputStream is = null;
    try {
      is = new ASN1InputStream(signatureValue);
      ASN1Primitive obj = is.readObject();
      return obj != null;
    } catch (IOException e) {
      return false;
    } finally {
      Utils.closeQuietly(is);
    }
  }

  private static String bytesToHex(byte[] bytes, int maxLen) {
    char[] hexChars = new char[min(bytes.length, maxLen) * 2];
    for (int j = 0; j < min(bytes.length, maxLen); j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  @Override
  protected Signature invokeSigningProcess() {
    logger.info("Signing BDoc container");
    signatureParameters.setSigningCertificate(signatureToken.getCertificate());
    byte[] dataToSign = getDataToBeSigned();
    Signature result = null;
    byte[] signatureValue = null;
    int count = 0;
    boolean finalized = false;
    while (!finalized && count < maxTryCount) {
      try {
        // TODO: Investigate instability (of BouncyCastle?)
        // Sometimes sign returns value what causes error in finalizeSignature
        signatureValue = signatureToken.sign(signatureParameters.getDigestAlgorithm(), dataToSign);
        if (signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA
            && isAsn1Encoded(signatureValue)) {
          signatureValue = DSSSignatureUtils.convertToXmlDSig(eu.europa.esig.dss.EncryptionAlgorithm.ECDSA, signatureValue);
        }
        result = finalizeSignature(signatureValue);
        finalized = true;
      } catch (TechnicalException e) {
        logger.warn("PROBLEM with signing [" + String.valueOf(count) + "]:" +
            bytesToHex(dataToSign, hexMaxlen) + " -> " + bytesToHex(signatureValue, hexMaxlen));
        count++;
      }
    }
    return result;
  }

  @Override
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException {
    byte[] dataToSign = getDataToBeSigned();
    byte[] digestToSign = calculateDigestToSign(dataToSign);
    return new DataToSign(digestToSign, signatureParameters, this);
  }

  @Override
  public Signature openAdESSignature(byte[] signatureDocument) {
    if (signatureDocument == null) {
      logger.error("Signature cannot be empty");
      throw new InvalidSignatureException();
    }
    InMemoryDocument document = new InMemoryDocument(signatureDocument);
    return createSignature(document);
  }

  @Override
  public Signature finalizeSignature(byte[] signatureValueBytes) {
    logger.info("Finalizing BDoc signature: " + bytesToHex(signatureValueBytes, hexMaxlen));
    populateParametersForFinalizingSignature(signatureValueBytes);
    Collection<DataFile> dataFilesToSign = getDataFiles();
    validateDataFilesToSign(dataFilesToSign);
    DSSDocument signedDocument = facade.signDocument(signatureValueBytes, dataFilesToSign);
    return createSignature(signedDocument);
  }

  protected Signature createSignature(DSSDocument signedDocument) {
    logger.debug("Opening signed document validator");
    Configuration configuration = getConfiguration();
    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(getDataFiles());
    List<DSSDocument> detachedContents = detachedContentCreator.getDetachedContentList();
    BDocSignatureOpener signatureOpener = new BDocSignatureOpener(detachedContents, configuration);
    List<BDocSignature> signatureList = signatureOpener.parse(signedDocument);
    BDocSignature signature = signatureList.get(0); //Only one signature was created
    validateOcspResponse(signature.getOrigin());
    policyDefinedByUser = null;
    logger.info("Signing BDoc successfully completed");
    return signature;
  }

  protected byte[] getDataToBeSigned() {
    logger.info("Getting data to sign");
    initSigningFacade();
    populateSignatureParameters();
    Collection<DataFile> dataFilesToSign = getDataFiles();
    validateDataFilesToSign(dataFilesToSign);
    byte[] dataToSign = facade.getDataToSign(dataFilesToSign);
    String signatureId = facade.getSignatureId();
    signatureParameters.setSignatureId(signatureId);
    return dataToSign;
  }

  protected void populateSignatureParameters() {
    setDigestAlgorithm();
    setEncryptionAlgorithm();
    setSignatureProfile();
    setSignerInformation();
    setSignatureId();
    setSignaturePolicy();
    setSigningCertificate();
    setSigningDate();
    setTimeStampProviderSource();
  }

  protected void populateParametersForFinalizingSignature(byte[] signatureValueBytes) {
    if (facade == null) {
      initSigningFacade();
      populateSignatureParameters();
    }
    Configuration configuration = getConfiguration();
    facade.setCertificateSource(configuration.getTSL());
    setOcspSource(signatureValueBytes);
  }

  protected void initSigningFacade() {
    if (facade == null) {
      facade = new XadesSigningDssFacade();
    }
  }

  protected byte[] calculateDigestToSign(byte[] dataToDigest) {
    DigestAlgorithm digestAlgorithm = signatureParameters.getDigestAlgorithm();
    return DSSUtils.digest(digestAlgorithm.getDssDigestAlgorithm(), dataToDigest);
  }

  protected Configuration getConfiguration() {
    if (container instanceof AsicSContainer) {
      return ((AsicSContainer) container).getConfiguration();
    }
    return ((BDocContainer) container).getConfiguration();
  }

  protected List<DataFile> getDataFiles() {
    return container.getDataFiles();
  }

  protected void validateOcspResponse(XadesSignature xadesSignature) {
    if (isBaselineSignatureProfile()) {
      return;
    }
    List<BasicOCSPResp> ocspResponses = xadesSignature.getOcspResponses();
    if (ocspResponses == null || ocspResponses.isEmpty()) {
      logger.error("Signature does not contain OCSP response");
      throw new OCSPRequestFailedException(xadesSignature.getId());
    }
  }

  protected boolean isBaselineSignatureProfile() {
    return signatureParameters.getSignatureProfile() != null
        && (SignatureProfile.B_BES == signatureParameters.getSignatureProfile()
        || SignatureProfile.B_EPES == signatureParameters.getSignatureProfile());
  }

  protected void setOcspSource(byte[] signatureValueBytes) {
    SKOnlineOCSPSource ocspSource = anOcspSource().
        withSignatureProfile(signatureParameters.getSignatureProfile()).
        withSignatureValue(signatureValueBytes).
        withConfiguration(getConfiguration()).
        build();
    facade.setOcspSource(ocspSource);
  }

  protected void setTimeStampProviderSource() {
    Configuration configuration = getConfiguration();
    OnlineTSPSource tspSource = new OnlineTSPSource(configuration.getTspSource());
    SkDataLoader dataLoader = SkDataLoader.createTimestampDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(signatureParameters.getSignatureProfile());
    tspSource.setDataLoader(dataLoader);
    facade.setTspSource(tspSource);
  }

  protected void setDigestAlgorithm() {
    if (signatureParameters.getDigestAlgorithm() == null) {
      Configuration configuration = getConfiguration();
      signatureParameters.setDigestAlgorithm(configuration.getSignatureDigestAlgorithm());
    }
    facade.setSignatureDigestAlgorithm(signatureParameters.getDigestAlgorithm());
  }

  protected void setEncryptionAlgorithm() {
    if (signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA || isEcdsaCertificate()) {
      logger.debug("Using ECDSA encryption algorithm");
      facade.setEncryptionAlgorithm(eu.europa.esig.dss.EncryptionAlgorithm.ECDSA);
    }
  }

  protected boolean isEcdsaCertificate() {
    X509Certificate certificate = signatureParameters.getSigningCertificate();
    String algorithm = certificate.getPublicKey().getAlgorithm();
    return algorithm.equals("EC") || algorithm.equals("ECC");
  }

  protected void setSignatureProfile() {
    if (signatureParameters.getSignatureProfile() != null) {
      setSignatureProfile(signatureParameters.getSignatureProfile());
    } else {
      SignatureProfile signatureProfile = getConfiguration().getSignatureProfile();
      setSignatureProfile(signatureProfile);
      signatureParameters.setSignatureProfile(signatureProfile);
    }
  }

  protected void setSignatureProfile(SignatureProfile profile) {
    switch (profile) {
      case B_BES:
        facade.setSignatureLevel(XAdES_BASELINE_B);
        break;
      case B_EPES:
        facade.setSignatureLevel(XAdES_BASELINE_B);
        break;
      case LTA:
        facade.setSignatureLevel(XAdES_BASELINE_LTA);
        break;
      default:
        facade.setSignatureLevel(XAdES_BASELINE_LT);
    }
  }

  protected void setSignaturePolicy() {
    /*
    if (isTimeMarkProfile() || isEpesProfile()) {
      Policy signaturePolicy = createBDocSignaturePolicy();
      facade.setSignaturePolicy(signaturePolicy);
    }
    */
    Policy signaturePolicy = new Policy();
    facade.setSignaturePolicy(signaturePolicy);
  }

  protected void setSignatureId() {
    if (StringUtils.isNotBlank(signatureParameters.getSignatureId())) {
      facade.setSignatureId(signatureParameters.getSignatureId());
    }
  }

  protected void setSignerInformation() {
    logger.debug("Adding signer information");
    List<String> signerRoles = signatureParameters.getRoles();
    if (!(isEmpty(signatureParameters.getCity()) && isEmpty(signatureParameters.getStateOrProvince())
        && isEmpty(signatureParameters.getPostalCode())
        && isEmpty(signatureParameters.getCountry()))) {

      SignerLocation signerLocation = new SignerLocation();

      if (!isEmpty(signatureParameters.getCity()))
        signerLocation.setLocality(signatureParameters.getCity());
      if (!isEmpty(signatureParameters.getStateOrProvince()))
        signerLocation.setStateOrProvince(signatureParameters.getStateOrProvince());
      if (!isEmpty(signatureParameters.getPostalCode()))
        signerLocation.setPostalCode(signatureParameters.getPostalCode());
      if (!isEmpty(signatureParameters.getCountry()))
        signerLocation.setCountry(signatureParameters.getCountry());
      facade.setSignerLocation(signerLocation);
    }
    facade.setSignerRoles(signerRoles);
  }

  protected void setSigningCertificate() {
    X509Certificate signingCert = signatureParameters.getSigningCertificate();
    facade.setSigningCertificate(signingCert);
  }

  protected void setSigningDate() {
    if (signingDate == null) {
      signingDate = new Date();
    }
    facade.setSigningDate(signingDate);
    logger.debug("Signing date is going to be " + signingDate);
  }

  protected void validateDataFilesToSign(Collection<DataFile> dataFilesToSign) {
    if (dataFilesToSign.isEmpty()) {
      logger.error("Container does not contain any data files");
      throw new ContainerWithoutFilesException();
    }
  }

  protected boolean isTimeMarkProfile() {
    if (signatureParameters.getSignatureProfile() == null) {
      return false;
    }
    return signatureParameters.getSignatureProfile() == SignatureProfile.LT_TM;
  }

  protected boolean isEpesProfile() {
    if (signatureParameters.getSignatureProfile() != null) {
      return signatureParameters.getSignatureProfile() == SignatureProfile.B_EPES;
    }
    return false;
  }
}
