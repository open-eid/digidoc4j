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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.tsl.AbstractTrustedListSignatureParametersBuilder;
import eu.europa.esig.dss.xades.tsl.TrustedListV5SignatureParametersBuilder;
import eu.europa.esig.dss.xades.tsl.TrustedListV6SignatureParametersBuilder;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.tsl.TslLoader;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.util.Map;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestTSLUtil {

  public static final String TSL_VERSION_IDENTIFIER = "{TSL_VERSION_IDENTIFIER}";
  public static final String OTHER_TSL_CERTIFICATE_B64 = "{OTHER_TSL_CERTIFICATE_B64}";
  public static final String OTHER_TSL_LOCATION = "{OTHER_TSL_LOCATION}";

  /**
   * This might be needed to validate already created containers that use test certificates but are timestamped by live TSA
   * @param configuration the configuration to add the certificate.
   * @return the same configuration with certificate added to TSL
   */
  public static Configuration addSkTsaCertificateToTsl(Configuration configuration) {
    return TestTSLUtil.addCertificateFromFileToTsl(configuration, "src/test/resources/testFiles/certs/SK_TSA.pem.crt");
  }

  public static Configuration addCertificateFromFileToTsl(Configuration configuration, String fileName) {
    try {
      FileInputStream fileInputStream = new FileInputStream(fileName);
      X509Certificate certificate = DSSUtils.loadCertificate(fileInputStream).getCertificate();
      configuration.getTSL().addTSLCertificate(certificate);
      fileInputStream.close();
      return configuration;
    } catch (DSSException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void evictCache() {
    TslLoader.invalidateCache();
  }

  public static long getCacheLastModified() {
    return TestTSLUtil.getCachedFile(TslLoader.fileCacheDirectory).lastModified();
  }

  private static File getCachedFile(File cacheDirectory) { // TODO refactor
    File cachedFile = null;
    if (cacheDirectory.exists()) {
      File[] files = cacheDirectory.listFiles();
      if (files != null && files.length > 0) {
        cachedFile = files[0];
        long modificationTime = cachedFile.lastModified();
        for (File file : files) {
          if (file.lastModified() > modificationTime) {
            cachedFile = file;
          }
        }
      }
    }
    return cachedFile;
  }

  public static boolean isTslCacheEmpty() {
    if(!TslLoader.fileCacheDirectory.exists()) {
      return true;
    }
    File[] cachedFiles = TslLoader.fileCacheDirectory.listFiles();
    return cachedFiles == null || cachedFiles.length == 0;
  }

  public static DSSDocument loadTslFromTemplate(DSSDocument templateDocument, Map<String, String> placeholderMappings) {
    try (InputStream inputStream = templateDocument.openStream()) {
      String documentAsString = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
      for (final Map.Entry<String, String> entry : placeholderMappings.entrySet()) {
        documentAsString = StringUtils.replace(documentAsString, entry.getKey(), entry.getValue());
      }
      return new InMemoryDocument(
              documentAsString.getBytes(StandardCharsets.UTF_8),
              templateDocument.getName(),
              templateDocument.getMimeType()
      );
    } catch (IOException e) {
      throw new IllegalStateException("Failed to process TSL template", e);
    }
  }

  public static DSSDocument signTslV5(DSSDocument tslXmlDocument, Pair<PrivateKey, CertificateToken> signer) {
    TrustedListV5SignatureParametersBuilder builder = new TrustedListV5SignatureParametersBuilder(
            signer.getValue(),
            tslXmlDocument
    );
    return signTsl(tslXmlDocument, builder, signer.getKey());
  }

  public static DSSDocument signTslV6(DSSDocument tslXmlDocument, Pair<PrivateKey, CertificateToken> signer) {
    TrustedListV6SignatureParametersBuilder builder = new TrustedListV6SignatureParametersBuilder(
            signer.getValue(),
            tslXmlDocument
    );
    return signTsl(tslXmlDocument, builder, signer.getKey());
  }

  private static DSSDocument signTsl(
          DSSDocument tslXmlDocument,
          AbstractTrustedListSignatureParametersBuilder signatureParametersBuilder,
          PrivateKey privateKey
  ) {
    if (privateKey instanceof ECKey) {
      int keyBitLength = ((ECKey) privateKey).getParams().getOrder().bitLength();
      if (keyBitLength <= 256) {
        signatureParametersBuilder.setDigestAlgorithm(DigestAlgorithm.SHA256);
      } else if (keyBitLength <= 384) {
        signatureParametersBuilder.setDigestAlgorithm(DigestAlgorithm.SHA384);
      } else {
        signatureParametersBuilder.setDigestAlgorithm(DigestAlgorithm.SHA512);
      }
    }
    XAdESSignatureParameters signatureParameters = signatureParametersBuilder.build();

    CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
    XAdESService signingService = new XAdESService(certificateVerifier);

    ToBeSigned toBeSigned = signingService.getDataToSign(tslXmlDocument, signatureParameters);
    byte[] signatureBytes = TestSigningUtil.encrypt(privateKey, toBeSigned.getBytes(), signatureParameters.getDigestAlgorithm());
    SignatureValue signatureValue = new SignatureValue(signatureParameters.getSignatureAlgorithm(), signatureBytes);
    return signingService.signDocument(tslXmlDocument, signatureParameters, signatureValue);
  }

  private TestTSLUtil() {}

}
