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

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.xades.signature.DSSSignatureUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureContainerMatcherValidator;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.asice.AsicESignatureOpener;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureOpener;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;
import org.digidoc4j.impl.asic.xades.XadesSigningDssFacade;
import org.digidoc4j.utils.CertificateUtils;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_B;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LT;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LTA;
import static org.apache.commons.lang3.StringUtils.isEmpty;

/**
 * Asic signature finalizer for datafiles signing process.
 */
public class AsicSignatureFinalizer extends SignatureFinalizer {

  public static final int HEX_MAX_LENGTH = 10;
  protected transient XadesSigningDssFacade facade;

  private static final Logger LOGGER = LoggerFactory.getLogger(AsicSignatureFinalizer.class);

  private Date signingDate;
  private boolean isLTorLTAProfile = false;

  public AsicSignatureFinalizer(List<DataFile> dataFilesToSign, SignatureParameters signatureParameters, Configuration configuration) {
    super(dataFilesToSign, signatureParameters, configuration);
  }

  @Override
  public Signature finalizeSignature(byte[] signatureValue) {
    if ((signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA || CertificateUtils.isEcdsaCertificate(signatureParameters.getSigningCertificate()))
            && DSSSignatureUtils.isAsn1Encoded(signatureValue)) {
      LOGGER.debug("Finalizing signature ASN1: {} [{}]", Helper.bytesToHex(signatureValue, HEX_MAX_LENGTH), signatureValue.length);
      signatureValue = DSSSignatureUtils.convertToXmlDSig(eu.europa.esig.dss.EncryptionAlgorithm.ECDSA,
              signatureValue);
    }
    LOGGER.debug("Finalizing signature XmlDSig: {} [{}]", Helper.bytesToHex(signatureValue, HEX_MAX_LENGTH), signatureValue.length);
    populateParametersForFinalizingSignature(signatureValue);
    validateSignatureCompatibility();
    validateDataFilesToSign(dataFiles);
    DSSDocument signedDocument = facade.signDocument(signatureValue, dataFiles);
    return createSignature(signedDocument);
  }

  @Override
  public Signature createSignature(DSSDocument signedDocument) {
    LOGGER.debug("Opening signed document validator");
    DetachedContentCreator detachedContentCreator;
    try {
      detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    } catch (Exception e) {
      LOGGER.error("Error in datafile processing: {}", e.getMessage());
      throw new DigiDoc4JException(e);
    }
    List<DSSDocument> detachedContents = detachedContentCreator.getDetachedContentList();
    XadesSignatureWrapper signatureWrapper = parseSignatureWrapper(signedDocument, detachedContents);

    AsicSignature signature;
    if (SignatureContainerMatcherValidator.isBDocOnlySignature(signatureParameters.getSignatureProfile())) {
      BDocSignatureOpener signatureOpener = new BDocSignatureOpener(configuration);
      signature = signatureOpener.open(signatureWrapper);
      validateOcspResponse(signature.getOrigin());
    } else {
      AsicESignatureOpener signatureOpener = new AsicESignatureOpener(configuration);
      signature = signatureOpener.open(signatureWrapper);
    }
    LOGGER.info("Signing asic successfully completed");
    return signature;
  }

  @Override
  public byte[] getDataToBeSigned() {
    LOGGER.info("Getting data to sign");

    initSigningFacade();
    validateDataFilesToSign(dataFiles);
    byte[] dataToSign = facade.getDataToSign(dataFiles);
    String signatureId = facade.getSignatureId();
    signatureParameters.setSignatureId(signatureId);
    return dataToSign;
  }

  protected void validateSignatureCompatibility() {
    // Do nothing
  }

  private void populateParametersForFinalizingSignature(byte[] signatureValueBytes) {
    initSigningFacade();
    facade.setCertificateSource(configuration.getTSL());
    setOcspSource(signatureValueBytes);
  }

  private void setOcspSource(byte[] signatureValueBytes) {
    SKOnlineOCSPSource ocspSource = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().
          withSignatureProfile(this.signatureParameters.getSignatureProfile()).
              withSignatureValue(signatureValueBytes).
              withConfiguration(configuration).
              build();
    this.facade.setOcspSource(ocspSource);
  }

  private void validateDataFilesToSign(Collection<DataFile> dataFilesToSign) {
    if (dataFilesToSign.isEmpty()) {
      LOGGER.error("Container does not contain any data files");
      throw new ContainerWithoutFilesException();
    }
  }

  private XadesSignatureWrapper parseSignatureWrapper(DSSDocument signatureDocument, List<DSSDocument> detachedContents) {
    AsicSignatureParser signatureParser = new AsicSignatureParser(detachedContents, configuration);
    XadesSignature xadesSignature = signatureParser.parse(signatureDocument);
    return new XadesSignatureWrapper(xadesSignature, signatureDocument);
  }

  private void validateOcspResponse(XadesSignature xadesSignature) {
    if (isBaselineSignatureProfile()) {
      return;
    }
    List<BasicOCSPResp> ocspResponses = xadesSignature.getOcspResponses();
    if (ocspResponses == null || ocspResponses.isEmpty()) {
      LOGGER.error("Signature does not contain OCSP response");
      throw new OCSPRequestFailedException(xadesSignature.getId());
    }
  }

  private boolean isBaselineSignatureProfile() {
    return signatureParameters.getSignatureProfile() != null
            && (SignatureProfile.B_BES == signatureParameters.getSignatureProfile()
            || SignatureProfile.B_EPES == signatureParameters.getSignatureProfile());
  }

  private void initSigningFacade() {
    if (facade == null) {
      facade = new XadesSigningDssFacade();
      populateFacadeParameters();
    }
  }

  private void populateFacadeParameters() {
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

  private void setDigestAlgorithm() {
    facade.setSignatureDigestAlgorithm(signatureParameters.getDigestAlgorithm());
  }

  private void setSigningCertificate() {
    X509Certificate signingCert = signatureParameters.getSigningCertificate();
    facade.setSigningCertificate(signingCert);
  }

  private void setEncryptionAlgorithm() {
    if (signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA) {
      LOGGER.debug("Using ECDSA encryption algorithm");
      facade.setEncryptionAlgorithm(eu.europa.esig.dss.EncryptionAlgorithm.ECDSA);
    } else {
      LOGGER.debug("Using RSA encryption algorithm");
      facade.setEncryptionAlgorithm(eu.europa.esig.dss.EncryptionAlgorithm.RSA);
    }
  }

  private void setSignatureProfile() {
    setSignatureProfile(signatureParameters.getSignatureProfile());
  }

  private void setSignatureProfile(SignatureProfile profile) {
    switch (profile) {
      case B_BES:
      case B_EPES:
        facade.setSignatureLevel(XAdES_BASELINE_B);
        break;
      case LTA:
        isLTorLTAProfile = true;
        facade.setSignatureLevel(XAdES_BASELINE_LTA);
        break;
      default:
        isLTorLTAProfile = true;
        facade.setSignatureLevel(XAdES_BASELINE_LT);
    }
  }

  private void setSignerInformation() {
    LOGGER.debug("Adding signer information");
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

  private void setSignatureId() {
    if (StringUtils.isNotBlank(signatureParameters.getSignatureId())) {
      facade.setSignatureId(signatureParameters.getSignatureId());
    }
  }

  protected void setSignaturePolicy() {
    // Do nothing
  }

  private void setSigningDate() {
    if (signingDate == null) {
      signingDate = new Date();
    }
    facade.setSigningDate(signingDate);
    LOGGER.debug("Signing date is going to be {}", signingDate);
  }

  private void setTimeStampProviderSource() {
    OnlineTSPSource tspSource = new OnlineTSPSource(this.getTspSource(configuration));
    SkDataLoader dataLoader = SkDataLoader.timestamp(configuration);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(this.signatureParameters.getSignatureProfile()));
    tspSource.setDataLoader(dataLoader);
    this.facade.setTspSource(tspSource);
  }

  private String getTspSource(Configuration configuration) {
    if (isLTorLTAProfile) {
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
