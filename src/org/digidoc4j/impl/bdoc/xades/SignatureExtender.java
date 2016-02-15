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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.validation102853.ocsp.BDocTSOcspSource;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignatureLevel;

public class SignatureExtender {

  private static final Logger logger = LoggerFactory.getLogger(SignatureExtender.class);
  private Configuration configuration;
  private DSSDocument detachedContent;

  public SignatureExtender(Configuration configuration, DSSDocument detachedContent) {
    this.configuration = configuration;
    this.detachedContent = detachedContent;
  }

  public List<DSSDocument> extend(Collection<DSSDocument> signaturesToExtend, SignatureProfile profile) {
    logger.debug("Extending signatures to " + profile);
    SignatureLevel signatureLevel = getSignatureLevel(profile);
    XadesSigningDssFacade extendingFacade = new XadesSigningDssFacade(configuration.getTspSource());
    extendingFacade.setCertificateSource(configuration.getTSL());
    BDocTSOcspSource ocspSource = new BDocTSOcspSource(configuration);
    ocspSource.setUserAgentSignatureProfile(profile);
    extendingFacade.setOcspSource(ocspSource);
    extendingFacade.setSignatureLevel(signatureLevel);
    List<DSSDocument> extendedSignatures = new ArrayList<>();
    for (DSSDocument xadesSignature : signaturesToExtend) {
      DSSDocument extendedSignature = extendingFacade.extendSignature(xadesSignature, detachedContent);
      extendedSignatures.add(extendedSignature);
    }
    logger.debug("Finished extending signatures");
    return extendedSignatures;
  }

  private SignatureLevel getSignatureLevel(SignatureProfile profile) {
    if (profile == SignatureProfile.LT) {
      return SignatureLevel.XAdES_BASELINE_LT;
    }
    if (profile == SignatureProfile.LTA) {
      return SignatureLevel.XAdES_BASELINE_LTA;
    }
    if (profile == SignatureProfile.LT_TM) {
      logger.error("It is not possible to extend the signature to LT_TM");
      throw new DigiDoc4JException("It is not possible to extend the signature to LT_TM");
    }
    logger.error("Extending signature to " + profile + " is not supported");
    throw new NotSupportedException("Extending signature to " + profile + " is not supported");
  }
}
