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

import static eu.europa.esig.dss.DigestAlgorithm.SHA256;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_B;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LT;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LTA;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.digidoc4j.impl.bdoc.ocsp.OcspSourceBuilder.anOcspSource;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
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
import org.digidoc4j.impl.SignatureFinalizer;
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

public class BDocSignatureBuilder extends SignatureBuilder implements SignatureFinalizer {

  private final static Logger logger = LoggerFactory.getLogger(BDocSignatureBuilder.class);
  private static final SignatureProfile DEFAULT_SIGNATURE_PROFILE = SignatureProfile.LT;
  private transient XadesSigningDssFacade facade;
  private Date signingDate;

  @Override
  protected Signature invokeSigningProcess() {
    logger.info("Signing BDoc container");
    signatureParameters.setSigningCertificate(signatureToken.getCertificate());
    byte[] dataToSign = getDataToBeSigned();
    byte[] signatureValue = signatureToken.sign(signatureParameters.getDigestAlgorithm(), dataToSign);
    return finalizeSignature(signatureValue);
  }

  @Override
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException {
    byte[] dataToSign = getDataToBeSigned();
    byte[] digestToSign = calculateDigestToSign(dataToSign);
    return new DataToSign(digestToSign, signatureParameters, this);
  }

  @Override
  public Signature openAdESSignature(byte[] signatureDocument) {
    if(signatureDocument == null) {
      logger.error("Signature cannot be empty");
      throw new InvalidSignatureException();
    }
    InMemoryDocument document = new InMemoryDocument(signatureDocument);
    return createSignature(document);
  }

  @Override
  public Signature finalizeSignature(byte[] signatureValueBytes) {
    logger.info("Finalizing BDoc signature");
    populateParametersForFinalizingSignature(signatureValueBytes);
    Collection<DataFile> dataFilesToSign = getDataFiles();
    validateDataFilesToSign(dataFilesToSign);
    DSSDocument signedDocument = facade.signDocument(signatureValueBytes, dataFilesToSign);
    return createSignature(signedDocument);
  }

  private Signature createSignature(DSSDocument signedDocument) {
    logger.debug("Opening signed document validator");
    Configuration configuration = getConfiguration();
    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(getDataFiles());
    List<DSSDocument> detachedContents = detachedContentCreator.getDetachedContentList();
    BDocSignatureOpener signatureOpener = new BDocSignatureOpener(detachedContents, configuration);
    List<BDocSignature> signatureList = signatureOpener.parse(signedDocument);
    BDocSignature signature = signatureList.get(0); //Only one signature was created
    validateOcspResponse(signature.getOrigin());
    logger.info("Signing BDoc successfully completed");
    return signature;
  }

  private byte[] getDataToBeSigned() {
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

  private void populateSignatureParameters() {
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

  private void populateParametersForFinalizingSignature(byte[] signatureValueBytes) {
    if (facade == null) {
      initSigningFacade();
      populateSignatureParameters();
    }
    Configuration configuration = getConfiguration();
    facade.setCertificateSource(configuration.getTSL());
    setOcspSource(signatureValueBytes);
  }

  private void initSigningFacade() {
    if (facade == null) {
      facade = new XadesSigningDssFacade();
    }
  }

  private byte[] calculateDigestToSign(byte[] dataToDigest) {
    DigestAlgorithm digestAlgorithm = signatureParameters.getDigestAlgorithm();
    return DSSUtils.digest(digestAlgorithm.getDssDigestAlgorithm(), dataToDigest);
  }

  private Configuration getConfiguration() {
    return ((BDocContainer) container).getConfiguration();
  }

  private List<DataFile> getDataFiles() {
    return container.getDataFiles();
  }

  private void validateOcspResponse(XadesSignature xadesSignature) {
    if(isBaselineSignatureProfile()) {
      return;
    }
    List<BasicOCSPResp> ocspResponses = xadesSignature.getOcspResponses();
    if (ocspResponses == null || ocspResponses.isEmpty()) {
      logger.error("Signature does not contain OCSP response");
      throw new OCSPRequestFailedException();
    }
  }

  private boolean isBaselineSignatureProfile() {
    return signatureParameters.getSignatureProfile() != null && (SignatureProfile.B_BES == signatureParameters.getSignatureProfile() || SignatureProfile.B_EPES == signatureParameters.getSignatureProfile());
  }

  private void setOcspSource(byte[] signatureValueBytes) {
    SKOnlineOCSPSource ocspSource = anOcspSource().
        withSignatureProfile(signatureParameters.getSignatureProfile()).
        withSignatureValue(signatureValueBytes).
        withConfiguration(getConfiguration()).
        build();
    facade.setOcspSource(ocspSource);
  }

  private void setTimeStampProviderSource() {
    Configuration configuration = getConfiguration();
    OnlineTSPSource tspSource = new OnlineTSPSource(configuration.getTspSource());
    SkDataLoader dataLoader = SkDataLoader.createTimestampDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(signatureParameters.getSignatureProfile());
    tspSource.setDataLoader(dataLoader);
    facade.setTspSource(tspSource);
  }

  private void setDigestAlgorithm() {
    if (signatureParameters.getDigestAlgorithm() == null) {
      signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    }
    facade.setSignatureDigestAlgorithm(signatureParameters.getDigestAlgorithm());
  }

  private void setEncryptionAlgorithm() {
    if (signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA || isEcdsaCertificate()) {
      logger.debug("Using ECDSA encryption algorithm");
      facade.setEncryptionAlgorithm(eu.europa.esig.dss.EncryptionAlgorithm.ECDSA);
    }
  }

  private boolean isEcdsaCertificate() {
    X509Certificate certificate = signatureParameters.getSigningCertificate();
    String algorithm = certificate.getPublicKey().getAlgorithm();
    return algorithm.equals("EC") || algorithm.equals("ECC");
  }

  private void setSignatureProfile() {
    if (signatureParameters.getSignatureProfile() != null) {
      setSignatureProfile(signatureParameters.getSignatureProfile());
    } else {
      setSignatureProfile(DEFAULT_SIGNATURE_PROFILE);
      signatureParameters.setSignatureProfile(DEFAULT_SIGNATURE_PROFILE);
    }
  }

  private void setSignatureProfile(SignatureProfile profile) {
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

  private void setSignaturePolicy() {
    if (isTimeMarkProfile() || isEpesProfile()) {
      Policy signaturePolicy = new Policy();
      signaturePolicy.setId("urn:oid:1.3.6.1.4.1.10015.1000.3.2.1");
      signaturePolicy.setDigestValue(decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="));
      signaturePolicy.setDigestAlgorithm(SHA256);
      signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
      facade.setSignaturePolicy(signaturePolicy);
    }
  }

  private boolean isEpesProfile() {
    if (signatureParameters.getSignatureProfile() != null) {
      return signatureParameters.getSignatureProfile() == SignatureProfile.B_EPES;
    }
    return false;
  }

  private void setSignatureId() {
    if (StringUtils.isNotBlank(signatureParameters.getSignatureId())) {
      facade.setSignatureId(signatureParameters.getSignatureId());
    }
  }

  private void setSignerInformation() {
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

  private void setSigningCertificate() {
    X509Certificate signingCert = signatureParameters.getSigningCertificate();
    facade.setSigningCertificate(signingCert);
  }

  private void setSigningDate() {
    if (signingDate == null) {
      signingDate = new Date();
    }
    facade.setSigningDate(signingDate);
    logger.debug("Signing date is going to be " + signingDate);
  }

  private void validateDataFilesToSign(Collection<DataFile> dataFilesToSign) {
    if (dataFilesToSign.isEmpty()) {
      logger.error("Container does not contain any data files");
      throw new ContainerWithoutFilesException();
    }
  }

  private boolean isTimeMarkProfile() {
    if(signatureParameters.getSignatureProfile() == null) {
      return false;
    }
    return signatureParameters.getSignatureProfile() == SignatureProfile.LT_TM;
  }
}
