/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */
package org.digidoc4j.test.util;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.digidoc4j.Configuration;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.impl.AiaSourceFactory;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.OcspDataLoaderFactory;
import org.digidoc4j.impl.TspDataLoaderFactory;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class DssContainerSigner {
  private final AIASource aiaSource;
  private final OCSPSource ocspSource;
  private final TSPSource tspSource;
  private final TrustedCertificateSource tsl;
  private final DigestAlgorithm signatureDigestAlgorithm;
  private final DigestAlgorithm referenceDigestAlgorithm;

  public DssContainerSigner(Configuration configuration) {
    Objects.requireNonNull(configuration);
    aiaSource = createAiaSource(configuration);
    ocspSource = createOcspSource(configuration);
    tspSource = createTspSource(configuration);
    tsl = (TrustedCertificateSource) configuration.getTSL();
    signatureDigestAlgorithm = Optional
        .ofNullable(configuration.getSignatureDigestAlgorithm())
        .orElse(DigestAlgorithm.SHA512);
    referenceDigestAlgorithm = Optional
        .ofNullable(configuration.getDataFileDigestAlgorithm())
        .orElse(DigestAlgorithm.SHA512);
  }

  public DSSDocument createSignedContainer(
        ASiCContainerType containerType,
        List <DSSDocument> dataFiles,
        SignatureLevel signatureLevel,
        SignatureToken signer) {
    ASiCWithXAdESService signatureService = new ASiCWithXAdESService(createCertificateVerifier());
    signatureService.setTspSource(tspSource);

    ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
    signatureParameters.aSiC().setContainerType(Objects.requireNonNull(containerType));
    signatureParameters.aSiC().setZipComment(true);
    signatureParameters.bLevel().setSigningDate(Date.from(Instant.now()));
    signatureParameters.setDetachedContents(dataFiles);
    signatureParameters.setDigestAlgorithm(signatureDigestAlgorithm.getDssDigestAlgorithm());
    signatureParameters.setReferenceDigestAlgorithm(referenceDigestAlgorithm.getDssDigestAlgorithm());
    signatureParameters.setSignatureLevel(Objects.requireNonNull(signatureLevel));
    signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    signatureParameters.setSigningCertificate(new CertificateToken(signer.getCertificate()));

    ToBeSigned dataToSign = signatureService.getDataToSign(dataFiles, signatureParameters);
    byte[] signatureBytes = signer.sign(signatureDigestAlgorithm, dataToSign.getBytes());
    SignatureValue signatureValue = new SignatureValue(signatureParameters.getSignatureAlgorithm(), signatureBytes);

    return signatureService.signDocument(dataFiles, signatureParameters, signatureValue);
  }

  private CertificateVerifier createCertificateVerifier() {
    CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
    certificateVerifier.setAIASource(aiaSource);
    certificateVerifier.setOcspSource(ocspSource);
    certificateVerifier.setTrustedCertSources(tsl);
    return certificateVerifier;
  }

  private static AIASource createAiaSource(Configuration configuration) {
    return new AiaSourceFactory(configuration).create();
  }

  private static OCSPSource createOcspSource(Configuration configuration) {
    CommonOCSPSource ocspSource = new CommonOCSPSource(configuration);
    ocspSource.setDataLoader(new OcspDataLoaderFactory(configuration).create());
    return ocspSource;
  }

  private static TSPSource createTspSource(Configuration configuration) {
    OnlineTSPSource tspSource = new OnlineTSPSource(configuration.getTspSource());
    tspSource.setDataLoader(new TspDataLoaderFactory(configuration).create());
    return tspSource;
  }
}
