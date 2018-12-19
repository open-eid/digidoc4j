/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic;

import static eu.europa.esig.dss.SignatureLevel.*;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.xades.signature.DSSSignatureUtils;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.*;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.AsicESignatureOpener;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureOpener;
import org.digidoc4j.impl.asic.asics.AsicSContainer;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSigningDssFacade;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Signature builder for Asic container.
 */
public class AsicSignatureBuilder extends SignatureBuilder implements SignatureFinalizer {

  private static final Logger logger = LoggerFactory.getLogger(AsicSignatureBuilder.class);
  private static final int hexMaxlen = 10;
  protected transient XadesSigningDssFacade facade;
  private Date signingDate;
  private boolean isLTorLTAprofile = false;

  @Override
  protected Signature invokeSigningProcess() {
    logger.info("Signing asic container");
    signatureParameters.setSigningCertificate(signatureToken.getCertificate());
    byte[] dataToSign = getDataToBeSigned();
    Signature result = null;
    byte[] signatureValue = null;
    try {
      signatureValue = signatureToken.sign(signatureParameters.getDigestAlgorithm(), dataToSign);
      result = finalizeSignature(signatureValue);
    } catch (TechnicalException e) {
      logger.warn("PROBLEM with signing: "
          + Helper.bytesToHex(dataToSign, hexMaxlen) + " -> " + Helper.bytesToHex(signatureValue, hexMaxlen));
    }
    return result;
  }

  @Override
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException {
    byte[] dataToSign = getDataToBeSigned();
    return new DataToSign(dataToSign, signatureParameters, this);
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
  public Signature finalizeSignature(byte[] signatureValue) {
    if ((signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA || isEcdsaCertificate())
        && DSSSignatureUtils.isAsn1Encoded(signatureValue)) {
      logger.debug("Finalizing signature ASN1: " + Helper.bytesToHex(signatureValue, hexMaxlen) + " ["
          + String.valueOf(signatureValue.length) + "]");
      signatureValue = DSSSignatureUtils.convertToXmlDSig(eu.europa.esig.dss.EncryptionAlgorithm.ECDSA,
          signatureValue);
    }
    logger.debug("Finalizing signature XmlDSig: " + Helper.bytesToHex(signatureValue, hexMaxlen) + " ["
        + String.valueOf(signatureValue.length) + "]");
    populateParametersForFinalizingSignature(signatureValue);
    Collection<DataFile> dataFilesToSign = getDataFiles();
    validateDataFilesToSign(dataFilesToSign);
    DSSDocument signedDocument = facade.signDocument(signatureValue, dataFilesToSign);
    return createSignature(signedDocument);
  }

  protected Signature createSignature(DSSDocument signedDocument) {
    logger.debug("Opening signed document validator");
    Configuration configuration = getConfiguration();
    DetachedContentCreator detachedContentCreator = null;
    try {
      detachedContentCreator = new DetachedContentCreator().populate(getDataFiles());
    } catch (Exception e) {
      logger.error("Error in datafile processing: " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
    List<DSSDocument> detachedContents = detachedContentCreator.getDetachedContentList();
    Signature signature = null;
    if (SignatureProfile.LT_TM.equals(this.signatureParameters.getSignatureProfile())) {
      BDocSignatureOpener signatureOpener = new BDocSignatureOpener(detachedContents, configuration);
      List<BDocSignature> signatureList = signatureOpener.parse(signedDocument);
      signature = signatureList.get(0); //Only one signature was created
      validateOcspResponse(((BDocSignature) signature).getOrigin());
    } else {
      AsicESignatureOpener signatureOpener = new AsicESignatureOpener(detachedContents, configuration);
      List<AsicESignature> signatureList = signatureOpener.parse(signedDocument);
      signature = signatureList.get(0); //Only one signature was created
    }
    policyDefinedByUser = null;
    logger.info("Signing asic successfully completed");
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
    setSigningCertificate();
    setEncryptionAlgorithm();
    setSignatureProfile();
    setSignerInformation();
    setSignatureId();
    setSignaturePolicy();
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

  public Configuration getConfiguration() {
    if (container instanceof AsicSContainer) {
      return ((AsicSContainer) container).getConfiguration();
    }
    if (container instanceof AsicEContainer) {
      return ((AsicEContainer) container).getConfiguration();
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
    SKOnlineOCSPSource ocspSource = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().
        withSignatureProfile(this.signatureParameters.getSignatureProfile()).
        withSignatureValue(signatureValueBytes).
        withConfiguration(getConfiguration()).
        build();
    this.facade.setOcspSource(ocspSource);
  }

  protected void setTimeStampProviderSource() {
    Configuration configuration = this.getConfiguration();
    OnlineTSPSource tspSource = new OnlineTSPSource(this.getTspSource(configuration));
    SkDataLoader dataLoader = SkDataLoader.timestamp(configuration);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(this.signatureParameters.getSignatureProfile()));
    tspSource.setDataLoader(dataLoader);
    this.facade.setTspSource(tspSource);
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
      signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
      facade.setEncryptionAlgorithm(eu.europa.esig.dss.EncryptionAlgorithm.ECDSA);
    } else {
      signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
      facade.setEncryptionAlgorithm(eu.europa.esig.dss.EncryptionAlgorithm.RSA);
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
        isLTorLTAprofile = true;
        facade.setSignatureLevel(XAdES_BASELINE_LTA);
        break;
      default:
        isLTorLTAprofile = true;
        facade.setSignatureLevel(XAdES_BASELINE_LT);
    }
  }

  protected void setSignaturePolicy() {
    if (policyDefinedByUser != null && isDefinedAllPolicyValues()) {
      facade.setSignaturePolicy(policyDefinedByUser);
    }
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

  protected boolean isTimeStampProfile() {
    if (signatureParameters.getSignatureProfile() == null) {
      return false;
    }
    return signatureParameters.getSignatureProfile() == SignatureProfile.LT;
  }

  protected boolean isEpesProfile() {
    if (signatureParameters.getSignatureProfile() != null) {
      return signatureParameters.getSignatureProfile() == SignatureProfile.B_EPES;
    }
    return false;
  }

  private String getTspSource(Configuration configuration) {
    if (isLTorLTAprofile) {
      X509Cert x509Cert = new X509Cert(signatureParameters.getSigningCertificate());
      String certCountry = x509Cert.getSubjectName(X509Cert.SubjectName.C);
      String tspSourceByCountry = configuration.getTspSourceByCountry(certCountry);
      if (StringUtils.isNotBlank(tspSourceByCountry)) {
        return tspSourceByCountry;
      }
    }
    return configuration.getTspSource();
  }

}
