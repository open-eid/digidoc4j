/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.B_EPES;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.digidoc4j.SignatureProfile.LT_TM;
import static org.digidoc4j.impl.bdoc.ocsp.OcspSourceBuilder.anOcspSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.digidoc4j.Configuration;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.digidoc4j.impl.bdoc.AsicSignatureBuilder;
import org.digidoc4j.impl.bdoc.SkDataLoader;
import org.digidoc4j.impl.bdoc.ocsp.SKOnlineOCSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

public class SignatureExtender {

  private static final Logger logger = LoggerFactory.getLogger(SignatureExtender.class);
  private static final Map<SignatureProfile, Set<SignatureProfile>> possibleExtensions = new HashMap<>(5);
  private Configuration configuration;
  private DSSDocument detachedContent;
  private List<DSSDocument> detachedContents;
  private XadesSigningDssFacade extendingFacade;

  static {
    possibleExtensions.put(B_BES, new HashSet<>(asList(LT, LTA)));
    possibleExtensions.put(B_EPES, new HashSet<>(singletonList(LT_TM)));
    possibleExtensions.put(LT, new HashSet<>(singletonList(LTA)));
    possibleExtensions.put(LT_TM, Collections.<SignatureProfile>emptySet());
    possibleExtensions.put(LTA, Collections.<SignatureProfile>emptySet());
  }

  public SignatureExtender(Configuration configuration, DSSDocument detachedContent) {
    this.configuration = configuration;
    this.detachedContent = detachedContent;
    extendingFacade = new XadesSigningDssFacade();
  }

  public SignatureExtender(Configuration configuration, List<DSSDocument> detachedContent) {
    this.configuration = configuration;
    this.detachedContents = detachedContent;
    extendingFacade = new XadesSigningDssFacade();
  }

  public List<DSSDocument> extend(List<Signature> signaturesToExtend, SignatureProfile profile) {
    logger.debug("Extending signatures to " + profile);
    validatePossibilityToExtendTo(signaturesToExtend, profile);
    prepareExtendingFacade(profile);
    List<DSSDocument> extendedSignatures = new ArrayList<>();
    for (Signature signature : signaturesToExtend) {
      DSSDocument extendedSignature = extendSignature((BDocSignature) signature, profile);
      extendedSignatures.add(extendedSignature);
    }
    logger.debug("Finished extending signatures");
    return extendedSignatures;
  }

  private void prepareExtendingFacade(SignatureProfile profile) {
    extendingFacade.setCertificateSource(configuration.getTSL());
    OnlineTSPSource tspSource = createTimeStampProviderSource(profile);
    extendingFacade.setTspSource(tspSource);
    SignatureLevel signatureLevel = getSignatureLevel(profile);
    extendingFacade.setSignatureLevel(signatureLevel);
    setSignaturePolicy(profile);
  }

  private DSSDocument extendSignature(BDocSignature signature, SignatureProfile profile) {
    OCSPSource ocspSource = createOcspSource(profile, signature.getOrigin().getSignatureValue());
    extendingFacade.setOcspSource(ocspSource);
    DSSDocument signatureDocument = signature.getSignatureDocument();
    return extendingFacade.extendSignature(signatureDocument, detachedContents);
  }

  private OCSPSource createOcspSource(SignatureProfile profile, byte[] signatureValue) {
    SKOnlineOCSPSource ocspSource = anOcspSource().
        withSignatureProfile(profile).
        withSignatureValue(signatureValue).
        withConfiguration(configuration).
        build();
    return ocspSource;
  }

  private OnlineTSPSource createTimeStampProviderSource(SignatureProfile profile) {
    OnlineTSPSource tspSource = new OnlineTSPSource(configuration.getTspSource());
    SkDataLoader dataLoader = SkDataLoader.createTimestampDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(profile);
    tspSource.setDataLoader(dataLoader);
    return tspSource;
  }

  private SignatureLevel getSignatureLevel(SignatureProfile profile) {
    if (profile == SignatureProfile.LT || profile == SignatureProfile.LT_TM) {
      return SignatureLevel.XAdES_BASELINE_LT;
    }
    if (profile == SignatureProfile.LTA) {
      return SignatureLevel.XAdES_BASELINE_LTA;
    }
    logger.error("Extending signature to " + profile + " is not supported");
    throw new NotSupportedException("Extending signature to " + profile + " is not supported");
  }

  private void setSignaturePolicy(SignatureProfile profile) {
    if (profile == LT_TM) {
      Policy signaturePolicy = AsicSignatureBuilder.createBDocSignaturePolicy();
      extendingFacade.setSignaturePolicy(signaturePolicy);
    }
  }

  private void validatePossibilityToExtendTo(List<Signature> signatures, SignatureProfile profile) {
    logger.debug("Validating if it's possible to extend all the signatures to " + profile);
    for (Signature signature : signatures) {
      if (!canExtendSignatureToProfile(signature, profile)) {
        String message = "It is not possible to extend " + signature.getProfile() + " signature to " + signature.getProfile() + ".";
        logger.error(message);
        throw new NotSupportedException(message);
      }
    }
  }

  private boolean canExtendSignatureToProfile(Signature signature, SignatureProfile profile) {
    return possibleExtensions.get(signature.getProfile()).contains(profile);
  }
}
