package org.digidoc4j;

import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_B;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LT;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LTA;
import static java.util.Arrays.asList;
import static org.apache.commons.lang3.StringUtils.isEmpty;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.exceptions.DataFileMissingException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.DetachedContentCreator;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.AsicESignatureOpener;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureOpener;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSigningDssFacade;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.xades.signature.DSSSignatureUtils;

public class DetachedXadesSignatureBuilder implements SignatureFinalizer {

  private static final Logger logger = LoggerFactory.getLogger(DetachedXadesSignatureBuilder.class);
  private static final int hexMaxlen = 10;

  private transient XadesSigningDssFacade facade;
  private List<DataFile> dataFiles = new ArrayList<>();
  private SignatureParameters signatureParameters = new SignatureParameters();
  private Configuration configuration;
  private SignatureToken signatureToken;
  protected static Policy policyDefinedByUser;
  private Date signingDate;
  private boolean isLTorLTAprofile = false;

  /**
   * Specify configuration for the builder.
   *
   * @param configuration configuration to be used for creating the signature.
   * @return builder for creating a signature.
   */
  public static DetachedXadesSignatureBuilder withConfiguration(Configuration configuration) {
    DetachedXadesSignatureBuilder builder = new DetachedXadesSignatureBuilder();
    builder.setConfiguration(configuration);
    return builder;
  }

  /**
   * Add a data file to builder.
   *
   * @param dataFile data file to be added to the builder.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withDataFile(DataFile dataFile) {
    dataFiles.add(dataFile);
    return this;
  }

  /**
   * Set a signing certificate to be used when creating data to be signed.
   *
   * @param certificate X509 signer's certificate.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSigningCertificate(X509Certificate certificate) {
    signatureParameters.setSigningCertificate(certificate);
    return this;
  }

  /**
   * Set signature digest algorithm used to generate a signature.
   *
   * @param digestAlgorithm signature digest algorithm.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSignatureDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    signatureParameters.setDigestAlgorithm(digestAlgorithm);
    return this;
  }

  /**
   * Set a city to the signature production place.
   *
   * @param cityName city to use on the signature production place.
   * @return builder for creating a signature
   */
  public DetachedXadesSignatureBuilder withCity(String cityName) {
    signatureParameters.setCity(cityName);
    return this;
  }

  /**
   * Set a state or province to the signature production place.
   *
   * @param stateOrProvince name of the state or province on the signature production place.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withStateOrProvince(String stateOrProvince) {
    signatureParameters.setStateOrProvince(stateOrProvince);
    return this;
  }

  /**
   * Set a postal code to the signature production place.
   *
   * @param postalCode postal code on the signature production place.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withPostalCode(String postalCode) {
    signatureParameters.setPostalCode(postalCode);
    return this;
  }

  /**
   * Set a country name to the signature production place.
   *
   * @param country name of the country on the signature production place.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withCountry(String country) {
    signatureParameters.setCountry(country);
    return this;
  }

  /**
   * Set roles to the signer.
   *
   * @param roles list of roles of a signer.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withRoles(String... roles) {
    if (signatureParameters.getRoles() == null) {
      signatureParameters.setRoles(asList(roles));
    } else {
      signatureParameters.getRoles().addAll(asList(roles));
    }
    return this;
  }

  /**
   * Set signature ID.
   *
   * @param signatureId signature id.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSignatureId(String signatureId) {
    signatureParameters.setSignatureId(signatureId);
    return this;
  }

  /**
   * Set encryption algorithm to be used in the signing process.
   *
   * @param encryptionAlgorithm encryption algorithm.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
    signatureParameters.setEncryptionAlgorithm(encryptionAlgorithm);
    return this;
  }

  /**
   * Set a signature profile: Time Mark, Time Stamp, Archive Time Stamp or no profile. Default is Time Stamp.
   *
   * @param signatureProfile signature profile.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSignatureProfile(SignatureProfile signatureProfile) {
    if (policyDefinedByUser != null && isDefinedAllPolicyValues()
        && signatureProfile != SignatureProfile.LT_TM) {
      logger.debug("policyDefinedByUser:" + policyDefinedByUser.toString());
      logger.debug("signatureProfile:" + signatureProfile.toString());
      throw new NotSupportedException("Can't define signature policy if it's not LT_TM signature profile ");
    }
    signatureParameters.setSignatureProfile(signatureProfile);
    return this;
  }

  /**
   * Set signature policy parameters. Define signature profile first.
   *
   * @param signaturePolicy with defined parameters.
   * @return SignatureBuilder
   */
  public DetachedXadesSignatureBuilder withOwnSignaturePolicy(Policy signaturePolicy) {
    if (signatureParameters.getSignatureProfile() != null
        && signatureParameters.getSignatureProfile() != SignatureProfile.LT_TM) {
      throw new NotSupportedException("Can't define signature policy if it's not LT_TM signature profile. Define it first. ");
    }
    policyDefinedByUser = signaturePolicy;
    return this;
  }

  /**
   * Set signature token to be used in the signing process.
   *
   * @param signatureToken signature token.
   * @return builder for creating a signature.
   */
  public DetachedXadesSignatureBuilder withSignatureToken(SignatureToken signatureToken) {
    this.signatureToken = signatureToken;
    return this;
  }

  /**
   * Creates data to be signed externally.
   * <p>
   * If the signing process involves signing the container externally (e.g. signing in the Web by a browser plugin),
   * then {@link DataToSign} provides necessary data for creating a signature externally.
   *
   * @return data to be signed externally.
   * @throws SignerCertificateRequiredException signer certificate must be provided using
   * {@link DetachedXadesSignatureBuilder#withSigningCertificate(X509Certificate)}
   * @throws DataFileMissingException builder must have at least one data file to be signed.
   */
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, DataFileMissingException {
    if (signatureParameters.getSigningCertificate() == null) {
      logger.error("Cannot invoke signing without signing certificate. Add 'withSigningCertificate()' method call or " +
          "call" +
          " 'withSignatureToken() instead.'");
      throw new SignerCertificateRequiredException();
    }
    byte[] dataToSign = getDataToBeSigned();
    return new DataToSign(dataToSign, signatureParameters, this);
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

  /**
   * Invokes a signing process on the container with a signature token (See {@link SignatureToken}).
   * Signature token must be provided with {@link DetachedXadesSignatureBuilder#withSignatureToken(SignatureToken)}.
   *
   * @return a new signature on the container.
   * @throws SignatureTokenMissingException if signature token is not provided with
   * {@link DetachedXadesSignatureBuilder#withSignatureToken(SignatureToken)}
   * @see SignatureToken
   */
  public Signature invokeSigning() throws SignatureTokenMissingException {
    if (signatureToken == null) {
      logger.error("Cannot invoke signing without signature token. Add 'withSignatureToken()' method call or call 'buildDataToSign() instead.'");
      throw new SignatureTokenMissingException();
    }
    return invokeSigningProcess();
  }

  /**
   * Creates signature object from XadES signature xml.
   *
   * @param signatureDocument XadES signature xml bytes.
   * @return builder for creating a signature.
   */
  public Signature openAdESSignature(byte[] signatureDocument) {
    if (signatureDocument == null) {
      logger.error("Signature cannot be empty");
      throw new InvalidSignatureException();
    }
    InMemoryDocument document = new InMemoryDocument(signatureDocument);
    return createSignature(document);
  }

  protected Signature invokeSigningProcess() {
    logger.info("Creating Xades Signature");
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

  protected boolean isEcdsaCertificate() {
    X509Certificate certificate = signatureParameters.getSigningCertificate();
    String algorithm = certificate.getPublicKey().getAlgorithm();
    return algorithm.equals("EC") || algorithm.equals("ECC");
  }

  protected void initSigningFacade() {
    if (facade == null) {
      facade = new XadesSigningDssFacade();
    }
  }

  protected List<DataFile> getDataFiles() {
    return dataFiles;
  }

  protected void validateDataFilesToSign(Collection<DataFile> dataFilesToSign) {
    if (dataFilesToSign.isEmpty()) {
      logger.error("Container does not contain any data files");
      throw new DataFileMissingException();
    }
  }

  protected void populateParametersForFinalizingSignature(byte[] signatureValueBytes) {
    if (facade == null) {
      initSigningFacade();
      populateSignatureParameters();
    }
    facade.setCertificateSource(configuration.getTSL());
    setOcspSource(signatureValueBytes);
  }

  protected void setOcspSource(byte[] signatureValueBytes) {
    SKOnlineOCSPSource ocspSource = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().
        withSignatureProfile(this.signatureParameters.getSignatureProfile()).
        withSignatureValue(signatureValueBytes).
        withConfiguration(configuration).
        build();
    this.facade.setOcspSource(ocspSource);
  }

  protected Signature createSignature(DSSDocument signedDocument) {
    logger.debug("Opening signed document validator");
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
    logger.info("Signing detached XadES successfully completed");
    return signature;
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

  protected void setSigningCertificate() {
    X509Certificate signingCert = signatureParameters.getSigningCertificate();
    facade.setSigningCertificate(signingCert);
  }

  protected void setDigestAlgorithm() {
    if (signatureParameters.getDigestAlgorithm() == null) {
      signatureParameters.setDigestAlgorithm(configuration.getSignatureDigestAlgorithm());
    }
    facade.setSignatureDigestAlgorithm(signatureParameters.getDigestAlgorithm());
  }

  protected void setTimeStampProviderSource() {
    OnlineTSPSource tspSource = new OnlineTSPSource(this.getTspSource(configuration));
    SkDataLoader dataLoader = SkDataLoader.timestamp(configuration);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(this.signatureParameters.getSignatureProfile()));
    tspSource.setDataLoader(dataLoader);
    this.facade.setTspSource(tspSource);
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

  protected void setSignatureProfile() {
    if (signatureParameters.getSignatureProfile() != null) {
      setSignatureProfile(signatureParameters.getSignatureProfile());
    } else {
      SignatureProfile signatureProfile = configuration.getSignatureProfile();
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

  protected static boolean isDefinedAllPolicyValues() {
    return StringUtils.isNotBlank(policyDefinedByUser.getId())
        && policyDefinedByUser.getDigestValue() != null
        && StringUtils.isNotBlank(policyDefinedByUser.getQualifier())
        && policyDefinedByUser.getDigestAlgorithm() != null
        && StringUtils.isNotBlank(policyDefinedByUser.getSpuri());
  }

  protected void setSignatureId() {
    if (StringUtils.isNotBlank(signatureParameters.getSignatureId())) {
      facade.setSignatureId(signatureParameters.getSignatureId());
    }
  }

  protected void setSignaturePolicy() {
    if (policyDefinedByUser != null && isDefinedAllPolicyValues()) {
      facade.setSignaturePolicy(policyDefinedByUser);
    }
  }

  protected void setSigningDate() {
    if (signingDate == null) {
      signingDate = new Date();
    }
    facade.setSigningDate(signingDate);
    logger.debug("Signing date is going to be " + signingDate);
  }

  protected void setConfiguration(Configuration configuration) {
    this.configuration = configuration;
  }

  public Configuration getConfiguration() {
    return configuration;
  }

}
