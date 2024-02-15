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

import org.apache.xml.security.signature.Reference;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.Signature;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.file.Paths;
import java.util.List;

public class UriEncodingTest extends AbstractTest {

  @Test
  // DetachedSignatureBuilder.createReference(...) uses UTF-8 from dss5.0
  public void signatureReferencesUseUriEncodingButManifestUsesPlainUtf8() {
    String fileName = "dds_JÜRIÖÖ € žŠ päev.txt";
    String expectedEncoding = "dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt";
    this.signAndAssert(fileName, expectedEncoding);
    // TODO: Also write an assertion to verify that the manifest file does NOT use URI encoding
  }

  @Test
  // DetachedSignatureBuilder.createReference(...) uses UTF-8 from dss5.0
  public void encodeDataFileWithSpecialCharacters() {
    String fileName = "et10i_0123456789!#$%&'()+,-. ;=@[]_`}~ et_EE";
    String expectedEncoding = "et10i_0123456789%21%23%24%25%26%27%28%29%2B%2C-.%20%3B%3D%40%5B%5D_%60%7D%7E%20et_EE";
    this.signAndAssert(fileName, expectedEncoding);
  }

  @Test
  public void validatePartialEncoding_shouldBeValid() {
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/et10_0123456789!#$%&'()+,-. ;=@[]_`}- et_EE_utf8.zip-d_ec.bdoc"), this.configuration);
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
  }

  @Test
  public void validateContainer_withWhitespaceEncodedAsPlus_shouldBeValid() {
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/M1n1 Testäöüõ!.txt-TS-d4j.bdoc"), this.configuration);
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "The reference data object has not been found!",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!"
    );
  }

  @Test
  public void validateContainer_withSpaceInDataFileNamePercentEncodedInSignature_shouldBeValid() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/space-in-datafile-name-percent-encoded-in-signature.asice",
            Configuration.of(Configuration.Mode.TEST)
    );
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
    assertHasNoWarnings(validationResult);
  }

  @Test
  public void validateContainer_withPlusInDataFileNamePercentEncodedInSignature_shouldBeValid() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/plus-in-datafile-name-percent-encoded-in-signature.asice",
            Configuration.of(Configuration.Mode.TEST)
    );
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
    assertHasNoWarnings(validationResult);
  }

  @Test
  public void validateContainer_withSpaceInDataFileNameEncodedAsPlusInSignature_shouldNotBeValid() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/invalid-containers/space-in-datafile-name-encoded-as-plus-in-signature.asice",
            Configuration.of(Configuration.Mode.TEST)
    );
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "The reference data object has not been found!",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!"
    );
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "The signature/seal is an INDETERMINATE AdES digital signature!"
    );
  }

  @Test
  public void validateContainer_withPlusInDataFileNameNotEncodedInSignature_shouldBeValid() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/plus-in-datafile-name-unencoded-in-signature.asice",
            Configuration.of(Configuration.Mode.TEST)
    );
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
    assertHasNoWarnings(validationResult);
  }

  /*
   * RESTRICTED METHODS
   */

  private void signAndAssert(String fileName, String expectedEncoding) {
    Signature signature = sign(fileName);
    Assert.assertTrue(signature.validateSignature().isValid());
    List<Reference> referencesInSignature = ((AsicESignature) signature).getOrigin().getReferences();
    Assert.assertEquals(expectedEncoding, referencesInSignature.get(0).getURI());
  }

  private Signature sign(String fileName) {
    return TestDataBuilderUtil.signContainer(ContainerBuilder.aContainer().
        withConfiguration(new Configuration(Configuration.Mode.TEST)).
        withDataFile(new ByteArrayInputStream("file contents".getBytes()), fileName, "application/octet-stream").
        build());
  }

}
