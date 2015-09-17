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
import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.BDocSignatureBuilder;
import org.digidoc4j.impl.ddoc.DDocSignatureBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class SignatureBuilder {

  private final static Logger logger = LoggerFactory.getLogger(SignatureBuilder.class);
  protected SignatureParameters signatureParameters = new SignatureParameters();
  protected SignatureToken signatureToken;
  protected static Map<String, Class<? extends SignatureBuilder>> customSignatureBuilders = new HashMap<>();

  public static SignatureBuilder aSignature(Container container) {
    SignatureBuilder builder = createBuilder(container);
    builder.setContainer(container);
    return builder;
  }

  private static SignatureBuilder createBuilder(Container container) {
    String containerType = container.getType();
    if(isCustomContainerType(containerType)) {
      return createCustomSignatureBuilder(containerType);
    } else if (isContainerType(containerType, BDOC_CONTAINER_TYPE)) {
      return new BDocSignatureBuilder();
    } else if (isContainerType(containerType, DDOC_CONTAINER_TYPE)) {
      return new DDocSignatureBuilder();
    } else {
      logger.error("Unknown container type: " + container.getType());
      throw new NotSupportedException("Unknown container type: " + container.getType());
    }
  }

  public Signature invokeSigning() throws SignatureTokenMissingException {
    if (signatureToken == null) {
      logger.error("Cannot invoke signing without signature token. Add 'withSignatureToken()' method call or call 'buildDataToSign() instead.'");
      throw new SignatureTokenMissingException();
    }
    return invokeSigningProcess();
  }

  public static <T extends SignatureBuilder> void setSignatureBuilderForContainerType(String containerType, Class<T> signatureBuilderClass) {
    customSignatureBuilders.put(containerType, signatureBuilderClass);
  }

  public static void removeCustomSignatureBuilders() {
    customSignatureBuilders.clear();
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

  protected void setContainer(Container container) {
    signatureParameters.setContainer(container);
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

  public abstract DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException;

  protected abstract Signature invokeSigningProcess();

  private static boolean isCustomContainerType(String containerType) {
    return customSignatureBuilders.containsKey(containerType);
  }

  private static boolean isContainerType(String containerType, String ddocContainerType) {
    return StringUtils.equalsIgnoreCase(ddocContainerType, containerType);
  }

  private static SignatureBuilder createCustomSignatureBuilder(String containerType) {
    Class<? extends SignatureBuilder> builderClass = customSignatureBuilders.get(containerType);
    try {
      logger.debug("Instantiating signature builder class " + builderClass.getName() + " for container type " + containerType);
      return builderClass.newInstance();
    } catch (ReflectiveOperationException e) {
      logger.error("Unable to instantiate custom signature builder class " + builderClass.getName() + " for type " + containerType);
      throw new TechnicalException("Unable to instantiate custom signature builder class " + builderClass.getName() + " for type " + containerType, e);
    }
  }
}
