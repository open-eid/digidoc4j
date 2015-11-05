/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.ContainerWithoutSignaturesException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Test;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;

public class AsicContainerValidatorTest {

  @Test(expected = ContainerWithoutSignaturesException.class)
  public void validatingContainer_withoutSignatures_shouldThrowException() throws Exception {
    String containerPath = "testFiles/asics_without_signatures.bdoc";
    AsicContainerValidator validator = createAsicContainerValidator(containerPath);
    validator.validate();
  }

  @Test(expected = ContainerWithoutSignaturesException.class)
  public void loadingContainerDetails_withoutSignatures_shouldThrowException() throws Exception {
    String containerPath = "testFiles/asics_without_signatures.bdoc";
    AsicContainerValidator validator = createAsicContainerValidator(containerPath);
    validator.loadContainerDetails();
  }

  @Test
  public void validContainer_withOneSignature_shouldReturnOneSignature() throws Exception {
    AsicContainerValidator validator = createAsicContainerValidator("testFiles/asics_with_one_signature.bdoc");
    AsicContainerValidationResult result = validator.validate();
    assertNotNull(result.getSignatures());
    assertFalse(result.getSignatures().isEmpty());
    assertEquals(1, result.getSignatures().size());
    assertNotNull(result.getContainerDigestAlgorithm());
    assertEquals(DigestAlgorithm.SHA256, result.getContainerDigestAlgorithm());
  }

  @Test
  public void validateInvalidContainer() throws Exception {
    AsicContainerValidator validator = createAsicContainerValidator("testFiles/TS-06_23634_TS_missing_OCSP_adjusted.asice");
    AsicContainerValidationResult result = validator.validate();
    assertFalse(result.isValid());
  }

  @Test
  public void validateTimestampWithUnknownTSAShouldBeInvalid() throws Exception {
    AsicContainerValidator validator = createAsicContainerValidator("testFiles/TS-05_23634_TS_unknown_TSA.asice");
    AsicContainerValidationResult result = validator.validate();
    assertFalse(result.isValid());
    assertEquals(result.getbDocValidationResult().getErrors().get(0).getMessage(), InvalidTimestampException.MESSAGE);
  }

  private AsicContainerValidator createAsicContainerValidator(String containerPath) {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    return createAsicContainerValidator(containerPath, configuration);
  }

  private AsicContainerValidator createAsicContainerValidator(String containerPath, Configuration configuration) {
    DSSDocument container = TestDataBuilder.createAsicContainer(containerPath);
    SKCommonCertificateVerifier commonCertificateVerifier = new SKCommonCertificateVerifier();
    commonCertificateVerifier.setCrlSource(null);
    commonCertificateVerifier.setOcspSource(null);
    TrustedListsCertificateSource trustedCertSource = configuration.getTSL();
    commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
    return new AsicContainerValidator(container, commonCertificateVerifier, configuration);
  }
}
