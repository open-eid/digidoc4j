/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import static java.util.Arrays.asList;

import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.exceptions.ContainerRequiredException;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.impl.bdoc.AsicFacade;
import org.digidoc4j.impl.ddoc.DDocFacade;
import org.digidoc4j.impl.bdoc.BDocContainer;
import org.digidoc4j.impl.bdoc.BDocDataToSign;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.impl.ddoc.DDocDataToSign;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureBuilder {

  private final static Logger logger = LoggerFactory.getLogger(SignatureBuilder.class);
  private SignatureParameters signatureParameters = new SignatureParameters();
  private SignatureToken signatureToken;

  public static SignatureBuilder aSignature() {
    return new SignatureBuilder();
  }

  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerRequiredException, ContainerWithoutFilesException, NotSupportedException {
    if (isContainerType("BDOC")) {
      return buildDataToSignForBDoc();
    } else if (isContainerType("DDOC")) {
      return buildDataToSignForDDoc();
    } else {
      logger.error("Unknown container type: " + signatureParameters.getContainer().getType());
      throw new NotSupportedException("Unknown container type: " + signatureParameters.getContainer().getType());
    }
  }

  public Signature invokeSigning() throws SignatureTokenMissingException, NotSupportedException, ContainerRequiredException {
    if (signatureToken == null) {
      logger.error("Cannot invoke signing without signature token. Add 'withSignatureToken()' method call or call 'buildDataToSign() instead.'");
      throw new SignatureTokenMissingException();
    }
    if (isContainerType("BDOC")) {
      return invokeBDocSigning();
    } else if (isContainerType("DDOC")) {
      return invokeDDocSigning();
    } else {
      logger.error("Unknown container type: " + signatureParameters.getContainer().getType());
      throw new NotSupportedException("Unknown container type: " + signatureParameters.getContainer().getType());
    }
  }

  private DataToSign buildDataToSignForBDoc() {
    AsicFacade asicFacade = getAsicFacade();
    asicFacade.setSignatureParameters(signatureParameters);
    SignedInfo signedInfo = asicFacade.prepareSigning(signatureParameters.getSigningCertificate());
    BDocDataToSign signature = new BDocDataToSign(signedInfo.getDigestToSign(), signedInfo.getSignatureParameters(), asicFacade);
    return signature;
  }

  private DataToSign buildDataToSignForDDoc() {
    DDocFacade ddocFacade = getJDigiDocFacade();
    ddocFacade.setSignatureParameters(signatureParameters);
    X509Certificate signingCertificate = signatureParameters.getSigningCertificate();
    SignedInfo signedInfo = ddocFacade.prepareSigning(signingCertificate);
    return new DDocDataToSign(signedInfo.getDigestToSign(), signatureParameters, ddocFacade);
  }

  private Signature invokeBDocSigning() {
    AsicFacade asicFacade = getAsicFacade();
    asicFacade.setSignatureParameters(signatureParameters);
    return asicFacade.sign(signatureToken);
  }

  private Signature invokeDDocSigning() {
    DDocFacade ddocFacade = getJDigiDocFacade();
    ddocFacade.setSignatureParameters(signatureParameters);
    return ddocFacade.sign(signatureToken);
  }

  public SignatureBuilder withCity(String cityName) {
    signatureParameters.setCity(cityName);
    return this;
  }

  public SignatureBuilder withStateOrProvince(String stateOrProvince) {
    signatureParameters.setStateOrProvince(stateOrProvince);
    return this;
  }

  public SignatureBuilder withPostalCode(String postalCode) {
    signatureParameters.setPostalCode(postalCode);
    return this;
  }

  public SignatureBuilder withCountry(String country) {
    signatureParameters.setCountry(country);
    return this;
  }

  public SignatureBuilder withRoles(String... roles) {
    if (signatureParameters.getRoles() == null) {
      signatureParameters.setRoles(asList(roles));
    } else {
      signatureParameters.getRoles().addAll(asList(roles));
    }
    return this;
  }

  public SignatureBuilder withDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    signatureParameters.setDigestAlgorithm(digestAlgorithm);
    return this;
  }

  public SignatureBuilder withSignatureProfile(SignatureProfile signatureProfile) {
    signatureParameters.setSignatureProfile(signatureProfile);
    return this;
  }

  public SignatureBuilder withContainer(Container container) {
    signatureParameters.setContainer(container);
    return this;
  }

  public SignatureBuilder withSigningCertificate(X509Certificate certificate) {
    signatureParameters.setSigningCertificate(certificate);
    return this;
  }

  public SignatureBuilder withSignatureId(String signatureId) {
    signatureParameters.setSignatureId(signatureId);
    return this;
  }

  public SignatureBuilder withSignatureToken(SignatureToken signatureToken) {
    this.signatureToken = signatureToken;
    return this;
  }

  private boolean isContainerType(String type) {
    return StringUtils.equalsIgnoreCase(signatureParameters.getContainer().getType(), type);
  }

  private AsicFacade getAsicFacade() {
    BDocContainer container = (BDocContainer) signatureParameters.getContainer();
    return container.getAsicFacade();
  }

  private DDocFacade getJDigiDocFacade() {
    DDocContainer container = (DDocContainer) signatureParameters.getContainer();
    return container.getJDigiDocFacade();
  }
}
