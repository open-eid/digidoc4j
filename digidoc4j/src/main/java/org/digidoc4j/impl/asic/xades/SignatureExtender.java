/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import org.digidoc4j.Configuration;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.AiaSourceFactory;
import org.digidoc4j.impl.TspDataLoaderFactory;
import org.digidoc4j.impl.asic.AsicSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.B_EPES;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.digidoc4j.SignatureProfile.LT_TM;

public class SignatureExtender {

  private static final Logger logger = LoggerFactory.getLogger(SignatureExtender.class);
  private static final Map<SignatureProfile, Set<SignatureProfile>> possibleExtensions = new HashMap<>(5);

  private final Configuration configuration;
  private final List<DSSDocument> detachedContents;
  private final XadesSigningDssFacade extendingFacade;

  static {
    possibleExtensions.put(B_BES, new HashSet<>(asList(LT, LTA)));
    possibleExtensions.put(B_EPES, emptySet());
    possibleExtensions.put(LT, singleton(LTA));
    possibleExtensions.put(LT_TM, emptySet());
    possibleExtensions.put(LTA, singleton(LTA));
  }

  public SignatureExtender(Configuration configuration, DSSDocument detachedContent) {
    this(configuration, singletonList(detachedContent));
  }

  public SignatureExtender(Configuration configuration, List<DSSDocument> detachedContent) {
    this.configuration = configuration;
    this.detachedContents = detachedContent;
    extendingFacade = new XadesSigningDssFacade();
  }

  public List<DSSDocument> extend(List<Signature> signaturesToExtend, SignatureProfile profile) {
    logger.debug("Extending signatures to {}", profile);
    validatePossibilityToExtendTo(signaturesToExtend, profile);
    prepareExtendingFacade(profile);
    List<DSSDocument> extendedSignatures = new ArrayList<>();
    for (Signature signature : signaturesToExtend) {
      DSSDocument extendedSignature = extendSignature(signature, profile);
      extendedSignatures.add(extendedSignature);
    }
    logger.debug("Finished extending signatures");
    return extendedSignatures;
  }

  private void prepareExtendingFacade(SignatureProfile profile) {
    extendingFacade.setCertificateSource(configuration.getTSL());
    OnlineTSPSource tspSource = createTimeStampProviderSource();
    extendingFacade.setTspSource(tspSource);
    SignatureLevel signatureLevel = getSignatureLevel(profile);
    extendingFacade.setSignatureLevel(signatureLevel);
    extendingFacade.setAiaSource(new AiaSourceFactory(configuration).create());
  }

  private DSSDocument extendSignature(Signature signature, SignatureProfile profile) {
    OCSPSource ocspSource = createOcspSource(profile, ((AsicSignature) signature).getOrigin().getSignatureValue());
    extendingFacade.setOcspSource(ocspSource);
    DSSDocument signatureDocument = ((AsicSignature) signature).getSignatureDocument();
    return extendingFacade.extendSignature(signatureDocument, detachedContents);
  }

  private OCSPSource createOcspSource(SignatureProfile profile, byte[] signatureValue) {
    return OCSPSourceBuilder.anOcspSource().withSignatureProfile(profile).withSignatureValue(signatureValue).
        withConfiguration(this.configuration).build();
  }

  private OnlineTSPSource createTimeStampProviderSource() {
    OnlineTSPSource source = new OnlineTSPSource(this.configuration.getTspSource());
    DataLoader loader = new TspDataLoaderFactory(this.configuration).create();
    source.setDataLoader(loader);
    return source;
  }

  private SignatureLevel getSignatureLevel(SignatureProfile profile) {
    if (profile == SignatureProfile.LT) {
      return SignatureLevel.XAdES_BASELINE_LT;
    }
    if (profile == SignatureProfile.LTA) {
      return SignatureLevel.XAdES_BASELINE_LTA;
    }
    logger.error("Extending signature to {} is not supported", profile);
    throw new NotSupportedException("Extending signature to " + profile + " is not supported");
  }

  private void validatePossibilityToExtendTo(List<Signature> signatures, SignatureProfile profile) {
    logger.debug("Validating if it's possible to extend all the signatures to {}", profile);
    for (Signature signature : signatures) {
      if (!canExtendSignatureToProfile(signature, profile)) {
        String message = "It is not possible to extend " + signature.getProfile() + " signature to " + profile + ".";
        logger.error(message);
        throw new NotSupportedException(message);
      }
    }
  }

  private boolean canExtendSignatureToProfile(Signature signature, SignatureProfile profile) {
    return possibleExtensions.getOrDefault(signature.getProfile(), emptySet()).contains(profile);
  }
}
