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
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.digidoc4j.Configuration;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.AiaSourceFactory;
import org.digidoc4j.impl.ArchiveTspSourceFactory;
import org.digidoc4j.impl.ExtendingOcspSourceFactory;
import org.digidoc4j.impl.SignatureTspSourceFactory;
import org.digidoc4j.impl.asic.AsicSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.digidoc4j.utils.ExtensionOrderUtils.getExtensionOrder;

public class SignatureExtender {

  private static final Logger logger = LoggerFactory.getLogger(SignatureExtender.class);

  private final Configuration configuration;
  private final List<DSSDocument> detachedContents;
  private final XadesSigningDssFacade extendingFacade;

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
    SignatureExtendingValidator.validateProfileExtendability(signaturesToExtend, profile);
    prepareExtendingFacade();
    List<DSSDocument> extendedSignatures = new ArrayList<>();
    for (Signature signature : signaturesToExtend) {
      DSSDocument extendedSignature = extendSignature(signature, profile);
      extendedSignatures.add(extendedSignature);
    }
    logger.debug("Finished extending signatures");
    return extendedSignatures;
  }

  private void prepareExtendingFacade() {
    extendingFacade.setCertificateSource(configuration.getTSL());
    extendingFacade.setAiaSource(new AiaSourceFactory(configuration).create());
    extendingFacade.setOcspSource(new ExtendingOcspSourceFactory(configuration).create());
    Optional.ofNullable(configuration.getArchiveTimestampDigestAlgorithm())
            .ifPresent(extendingFacade::setArchiveTimestampDigestAlgorithm);
  }

  private void prepareExtendingFacade(SignatureProfile profile) {
    extendingFacade.setTspSource(createTimeStampProviderSource(profile));
    extendingFacade.setSignatureLevel(getSignatureLevel(profile));
  }

  private DSSDocument extendSignature(Signature signature, SignatureProfile targetProfile) {
    List<SignatureProfile> intermediateProfiles = getExtensionOrder(signature.getProfile(), targetProfile);
    if (signature.getProfile() != LTA) {
      intermediateProfiles.remove(signature.getProfile());
    }

    DSSDocument signatureDocument = ((AsicSignature) signature).getSignatureDocument();
    for (SignatureProfile intermediateProfile : intermediateProfiles) {
      prepareExtendingFacade(intermediateProfile);
      signatureDocument = extendingFacade.extendSignature(signatureDocument, detachedContents);
    }
    return signatureDocument;
  }

  private TSPSource createTimeStampProviderSource(SignatureProfile profile) {
    switch (profile) {
      case T:
      case LT:
        return new SignatureTspSourceFactory(configuration).create();
      case LTA:
        return new ArchiveTspSourceFactory(configuration).create();
      default:
        return null;
    }
  }

  private SignatureLevel getSignatureLevel(SignatureProfile profile) {
    if (profile == SignatureProfile.T) {
      return SignatureLevel.XAdES_BASELINE_T;
    }
    if (profile == SignatureProfile.LT) {
      return SignatureLevel.XAdES_BASELINE_LT;
    }
    if (profile == SignatureProfile.LTA) {
      return SignatureLevel.XAdES_BASELINE_LTA;
    }
    logger.error("Extending signature to {} is not supported", profile);
    throw new NotSupportedException("Extending signature to " + profile + " is not supported");
  }
}
