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

import static org.digidoc4j.impl.bdoc.ocsp.OcspSourceBuilder.anOcspSource;

import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.digidoc4j.impl.bdoc.SkDataLoader;
import org.digidoc4j.impl.bdoc.ocsp.SKOnlineOCSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

public class SignatureExtender {

  private static final Logger logger = LoggerFactory.getLogger(SignatureExtender.class);
  private Configuration configuration;
  private DSSDocument detachedContent;
  private XadesSigningDssFacade extendingFacade;

  public SignatureExtender(Configuration configuration, DSSDocument detachedContent) {
    this.configuration = configuration;
    this.detachedContent = detachedContent;
    extendingFacade = new XadesSigningDssFacade();
  }

  public List<DSSDocument> extend(List<Signature> signaturesToExtend, SignatureProfile profile) {
    logger.debug("Extending signatures to " + profile);
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
  }

  private DSSDocument extendSignature(BDocSignature signature, SignatureProfile profile) {
    OCSPSource ocspSource = createOcspSource(profile, signature.getOrigin().getSignatureValue());
    extendingFacade.setOcspSource(ocspSource);
    DSSDocument signatureDocument = signature.getSignatureDocument();
    return extendingFacade.extendSignature(signatureDocument, detachedContent);
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
}
