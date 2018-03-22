/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.report;

import java.nio.file.Paths;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.MimeType;

public class ValidationReportTest extends AbstractTest {

  @Test
  public void validContainerWithOneSignature() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    Signature signature = this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    String signatureId = signature.getId();
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    String report = result.getReport();
    TestAssert.assertXPathHasValue("1", "//SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue(signatureId, "/SimpleReport/Signature/@Id", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature[@Id='" + signatureId + "']/SignedBy", report);
    TestAssert.assertXPathHasValue("TOTAL_PASSED", "/SimpleReport/Signature[@Id='" + signatureId + "']/Indication", report);
    TestAssert.assertXPathHasValue("Full document", "/SimpleReport/Signature[@Id='" + signatureId + "']/SignatureScope", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("", "/SimpleReport/Signature[@Id='" + signatureId + "']/Errors", report);
  }

  @Test
  public void validContainerWithOneTmSignature() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    container.addDataFile("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf", MimeType.PDF.getMimeTypeString());
    this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("XAdES_BASELINE_LT_TM", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("TOTAL_PASSED", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope[1]/@name", report);
    TestAssert.assertXPathHasValue("dds_acrobat.pdf", "/SimpleReport/Signature/SignatureScope[2]/@name", report);
  }

  @Test
  public void containerWithOneBesSignature() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-B", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("TRY_LATER", "/SimpleReport/Signature/SubIndication", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void containerWithOneEpesSignature() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    this.createSignatureBy(container, SignatureProfile.B_EPES, this.pkcs12SignatureToken);
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("XAdES_BASELINE_B_EPES", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("TRY_LATER", "/SimpleReport/Signature/SubIndication", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void validContainerWithTwoSignatures() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    Signature signature1 = this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    Signature signature2 = this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    String report = result.getReport();
    TestAssert.assertXPathHasValue("2", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("2", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue(signature1.getId(), "/SimpleReport/Signature[1]/@Id", report);
    TestAssert.assertXPathHasValue(signature2.getId(), "/SimpleReport/Signature[2]/@Id", report);
    TestAssert.assertXPathHasValue("XAdES_BASELINE_LT_TM", "/SimpleReport/Signature[1]/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature[2]/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature[1]/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature[2]/SignatureScope/@name", report);
  }

  @Test
  public void invalidContainerWithOneSignature() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/invalid-containers/bdoc-tm-ocsp-revoked.bdoc");
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    String report = result.getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("XAdES_BASELINE_LT_TM", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature/SignedBy", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("NO_POE", "/SimpleReport/Signature/SubIndication", report);
    TestAssert.assertXPathHasValue("The past signature validation is not conclusive!", "/SimpleReport/Signature/Errors", report);
    TestAssert.assertXPathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void invalidContainerWithManifestErrors() throws Exception {
    Container container = TestDataBuilderUtil.open
        ("src/test/resources/prodFiles/invalid-containers/filename_mismatch_manifest.asice");
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    String report = result.getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-T", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("NO_CERTIFICATE_CHAIN_FOUND", "/SimpleReport/Signature/SubIndication", report);
    TestAssert.assertXPathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    TestAssert.assertXPathHasValue("RELEASE-NOTES.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("The certificate chain for signature is not trusted, there is no trusted anchor.", "/SimpleReport/Signature/Errors", report);
    TestAssert.assertXPathHasValue("Manifest file has an entry for file <incorrect.txt> with mimetype <text/plain> " +
        "but the signature file for signature S0 does not have an entry for this file", "/SimpleReport/ContainerError[1]", report);
    TestAssert.assertXPathHasValue("The signature file for signature S0 has an entry for file <RELEASE-NOTES.txt> " +
        "with mimetype <text/plain> but the manifest file does not have an entry for this file",
        "/SimpleReport/ContainerError[2]", report);
  }

  @Test
  public void containerWithoutSignatures() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("0", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
  }

  @Test
  public void signatureContainsAdditionalErrors() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/invalid-containers/TS-08_23634_TS_OCSP_before_TS.asice");
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-T", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("ŽAIKOVSKI,IGOR,37101010021", "/SimpleReport/Signature/SignedBy", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("The result of the timestamps validation process is not conclusive!", "/SimpleReport/Signature/Errors[1]", report);
    TestAssert.assertXPathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
