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

import org.digidoc4j.AbstractTest;
import org.digidoc4j.CompositeContainerBuilder;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.TestConstants;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Test;

import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

public class ValidationReportTest extends AbstractTest {

  @Test
  public void validContainerWithOneSignature() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    Signature signature = this.createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    String signatureId = signature.getId();
    String signatureUniqueId = signature.getUniqueId();
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    String report = result.getReport();
    TestAssert.assertXPathHasValue("1", "//SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue(signatureId, "/SimpleReport/Signature/@Id", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature[@Id='" + signatureId + "']/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001013739", "/SimpleReport/Signature[@Id='" + signatureId + "']/SignedBy", report);
    TestAssert.assertXPathHasValue("TOTAL_PASSED", "/SimpleReport/Signature[@Id='" + signatureId + "']/Indication", report);
    TestAssert.assertXPathHasValue("Full document", "/SimpleReport/Signature[@Id='" + signatureId + "']/SignatureScope", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature[@Id='" + signatureId + "']/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("", "/SimpleReport/Signature[@Id='" + signatureId + "']/Errors", report);
    TestAssert.assertXPathHasValue("true", "count(/SimpleReport/Signature[@Id='" + signatureId + "']/CertificateChain/Certificate) > 1", report);
    TestAssert.assertXPathHasValue("O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001013739", "/SimpleReport/Signature[@Id='" + signatureId +
            "']/CertificateChain/Certificate[1]/qualifiedName", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature[@Id='" + signatureId + "']/SigningTime)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature[@Id='" + signatureId + "']/BestSignatureTime)", report);
  }

  @Test
  public void validContainerWithOneTmSignature() throws Exception {
    Container container = TestDataBuilderUtil.open(BDOC_WITH_TM_SIG);
    String report = container.validate().getReport();
    Signature signature = container.getSignatures().get(0);
    String signatureId = signature.getId();
    String signatureUniqueId = signature.getUniqueId();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue(signatureId, "/SimpleReport/Signature/@Id", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature[@Id='" + signatureId + "']/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT-TM", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("TOTAL_PASSED", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope[1]/@name", report);
    TestAssert.assertXPathHasValue("true", "count(/SimpleReport/Signature/CertificateChain/Certificate) > 1", report);
    TestAssert.assertXPathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature/CertificateChain/Certificate[1]/qualifiedName", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature/SigningTime)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature/BestSignatureTime)", report);
  }

  @Test
  public void containerWithOneBesSignature() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    Signature signature = this.createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    String signatureId = signature.getId();
    String signatureUniqueId = signature.getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue(signatureId, "/SimpleReport/Signature/@Id", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature[@Id='" + signatureId + "']/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-B", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("CERTIFICATE_CHAIN_GENERAL_FAILURE", "/SimpleReport/Signature/SubIndication", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("true", "count(/SimpleReport/Signature/CertificateChain/Certificate) > 1", report);
    TestAssert.assertXPathHasValue("O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001013739", "/SimpleReport/Signature/CertificateChain/Certificate[1]/qualifiedName", report);
  }

  @Test
  public void containerWithOneEpesSignature() throws Exception {
    Container container = TestDataBuilderUtil.open(BDOC_WITH_B_EPES_SIG);
    Signature signature = container.getSignatures().get(0);
    String signatureId = signature.getId();
    String signatureUniqueId = signature.getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue(signatureId, "/SimpleReport/Signature/@Id", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature[@Id='" + signatureId + "']/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-B-EPES", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("CERTIFICATE_CHAIN_GENERAL_FAILURE", "/SimpleReport/Signature/SubIndication", report);
    TestAssert.assertXPathHasValue("junit4090904941259216539.tmp", "/SimpleReport/Signature/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("true", "count(/SimpleReport/Signature/CertificateChain/Certificate) > 1", report);
    TestAssert.assertXPathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature/CertificateChain/Certificate[1]/qualifiedName", report);
  }

  @Test
  public void validContainerWithTwoSignatures() throws Exception {
    Container container = TestDataBuilderUtil.open(BDOC_WITH_TM_AND_TS_SIG);
    SignatureValidationResult result = container.validate();
    List<String> signatureUniqueIds = container.getSignatures().stream().map(Signature::getUniqueId).collect(Collectors.toList());
    Assert.assertTrue(result.isValid());
    String report = result.getReport();
    TestAssert.assertXPathHasValue("2", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("2", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("2", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue("id-6a5d6671af7a9e0ab9a5e4d49d69800d", "/SimpleReport/Signature[1]/@Id", report);
    TestAssert.assertXPathHasValue("id-df8be709dc86f84f4eb34d4ed3a946c4", "/SimpleReport/Signature[2]/@Id", report);
    TestAssert.assertXPathHasValue(signatureUniqueIds.get(0), "/SimpleReport/Signature[1]/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue(signatureUniqueIds.get(1), "/SimpleReport/Signature[2]/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT-TM", "/SimpleReport/Signature[1]/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature[2]/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature[1]/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature[2]/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("true", "count(/SimpleReport/Signature[1]/CertificateChain/Certificate) > 1", report);
    TestAssert.assertXPathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature[1]/CertificateChain/Certificate[1]/qualifiedName", report);
    TestAssert.assertXPathHasValue("true", "count(/SimpleReport/Signature[2]/CertificateChain/Certificate) > 1", report);
    TestAssert.assertXPathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature[2]/CertificateChain/Certificate[1]/qualifiedName", report);
  }

  @Test
  public void invalidContainerWithOneSignature() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/invalid-containers/bdoc-tm-ocsp-revoked.bdoc");
    SignatureValidationResult result = container.validate();
    String signatureUniqueId = container.getSignatures().get(0).getUniqueId();
    Assert.assertFalse(result.isValid());
    String report = result.getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature[1]/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT-TM", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature/SignedBy", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("REVOKED_NO_POE", "/SimpleReport/Signature/SubIndication", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature/Errors[.='The certificate validation is not conclusive!'])", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature/Errors[.='The certificate is revoked!'])", report);
    TestAssert.assertXPathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("true", "count(/SimpleReport/Signature/CertificateChain/Certificate) > 1", report);
    TestAssert.assertXPathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature/CertificateChain/Certificate[1]/qualifiedName", report);
  }

  @Test
  public void invalidContainerWithManifestErrors() throws Exception {
    Container container = TestDataBuilderUtil.open
        ("src/test/resources/prodFiles/invalid-containers/filename_mismatch_manifest.asice");
    SignatureValidationResult result = container.validate();
    String signatureUniqueId = container.getSignatures().get(0).getUniqueId();
    Assert.assertFalse(result.isValid());
    String report = result.getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature[1]/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-T", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("NO_CERTIFICATE_CHAIN_FOUND", "/SimpleReport/Signature/SubIndication", report);
    TestAssert.assertXPathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    TestAssert.assertXPathHasValue("RELEASE-NOTES.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature/Errors[.='Unable to build a certificate chain up to a trusted list!'])", report);
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
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/Signature)", report);
  }

  @Test
  public void unsignedAsiceContainerWithEmptyDataFiles() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/unsigned-container-with-empty-datafiles.asice");
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("0", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue("2", "count(/SimpleReport/ContainerWarning)", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file-2.txt' is empty", "/SimpleReport/ContainerWarning[1]", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file-4.txt' is empty", "/SimpleReport/ContainerWarning[2]", report);
  }

  @Test
  public void unsignedAsicsContainerWithEmptyDataFile() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/unsigned-container-with-empty-datafile.asics");
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("0", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/ContainerWarning)", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file.txt' is empty", "/SimpleReport/ContainerWarning", report);
  }

  @Test
  public void signedAsiceContainerWithEmptyDataFiles() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/signed-container-with-empty-datafiles.asice");
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue("2", "count(/SimpleReport/ContainerWarning)", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file-2.txt' is empty", "/SimpleReport/ContainerWarning[1]", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file-4.txt' is empty", "/SimpleReport/ContainerWarning[2]", report);
  }

  @Test
  public void signedBdocContainerWithEmptyDataFiles() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/signed-container-with-empty-datafiles.bdoc");
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue("2", "count(/SimpleReport/ContainerWarning)", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file-2.txt' is empty", "/SimpleReport/ContainerWarning[1]", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file-4.txt' is empty", "/SimpleReport/ContainerWarning[2]", report);
  }

  @Test
  public void signedAsicsContainerWithEmptyDataFile() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/signed-container-with-empty-datafile.asics");
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/ContainerWarning)", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file.txt' is empty", "/SimpleReport/ContainerWarning", report);
  }

  @Test
  public void timestampedAsicsContainerWithEmptyDataFile() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/timestamped-container-with-empty-datafile.asics");
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("0", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/ContainerWarning)", report);
    TestAssert.assertXPathHasValue("Data file 'empty-file.txt' is empty", "/SimpleReport/ContainerWarning", report);
  }

  @Test
  public void signatureContainsAdditionalErrors() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/invalid-containers/TS-08_23634_TS_OCSP_before_TS.asice");
    String signatureUniqueId = container.getSignatures().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature[1]/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-T", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("ŽAIKOVSKI,IGOR,37101010021", "/SimpleReport/Signature/SignedBy", report);
    TestAssert.assertXPathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature/Errors[.='Signature has an invalid timestamp'])", report);
    TestAssert.assertXPathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void signatureRevocationAndTimeStampDifferenceMoreThan15min() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/EE_LT_sig_OCSP_15m6s_after_TS.asice");
    String signatureUniqueId = container.getSignatures().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature[1]/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("JÕEORG,JAAK-KRISTJAN,38001085718", "/SimpleReport/Signature/SignedBy", report);
    TestAssert.assertXPathHasValue("TOTAL_PASSED", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("", "/SimpleReport/Signature/Errors", report);
    TestAssert.assertXPathHasValue("The time difference between the signature timestamp and the OCSP response exceeds 15 minutes, rendering the OCSP response not 'fresh'.",
            "/SimpleReport/Signature/Warnings", report);
    TestAssert.assertXPathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void validContainerWithOneTimestampToken() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics");
    String timestampUniqueId = container.getTimestamps().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("0", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue(timestampUniqueId, "/SimpleReport/TimestampToken/@Id", report);
    TestAssert.assertXPathHasValue(timestampUniqueId,"/SimpleReport/TimestampToken/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken/Indication", report);
    TestAssert.assertXPathHasValue("2024-05-28T12:24:09Z", "/SimpleReport/TimestampToken/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.DEMO_SK_TSA_2023E_CN, "/SimpleReport/TimestampToken/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken/TimestampLevel", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/TimestampToken/TimestampScope/@name", report);
  }

  @Test
  public void validTimestampedContainerWithNestedInvalidAsiceWithMultipleSignatures() throws Exception {
    String containerPath = "src/test/resources/testFiles/invalid-containers/one-valid-and-multiple-invalid-signatures.asice";
    String containerFilename = Paths.get(containerPath).getFileName().toString();
    Container container = CompositeContainerBuilder.fromContainerFile(containerPath)
            .withConfiguration(configuration).buildTimestamped(timestampBuilder -> {});
    String timestampUniqueId = container.getTimestamps().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue(timestampUniqueId,"/SimpleReport/TimestampToken/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken/Indication", report);
    TestAssert.assertXPathHasValue(containerFilename, "/SimpleReport/TimestampToken/TimestampScope/@name", report);
    TestAssert.assertXPathHasValue("9", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("3", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("9", "count(/SimpleReport/Signature)", report);
  }

  @Test
  public void validTimestampedContainerWithNestedValidBdoc() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/1xTST-valid-bdoc-data-file.asics");
    Container nestedContainer = TestDataBuilderUtil.open(container.getDataFiles().get(0));
    String timestampUniqueId = container.getTimestamps().get(0).getUniqueId();
    String signatureUniqueId = nestedContainer.getSignatures().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue(timestampUniqueId,"/SimpleReport/TimestampToken/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken/Indication", report);
    TestAssert.assertXPathHasValue("2024-03-27T12:42:57Z", "/SimpleReport/TimestampToken/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.DEMO_SK_TSA_2023E_CN, "/SimpleReport/TimestampToken/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken/TimestampLevel", report);
    TestAssert.assertXPathHasValue("valid-bdoc-tm.bdoc", "/SimpleReport/TimestampToken/TimestampScope/@name", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT-TM", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001016970", "/SimpleReport/Signature/SignedBy", report);
    TestAssert.assertXPathHasValue("TOTAL_PASSED", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("QESig", "/SimpleReport/Signature/SignatureLevel", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void valid2xTimestampedContainerWithNestedValidBdoc() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/2xTST-valid-bdoc-data-file.asics");
    Container nestedContainer = TestDataBuilderUtil.open(container.getDataFiles().get(0));
    String timestamp1UniqueId = container.getTimestamps().get(0).getUniqueId();
    String timestamp2UniqueId = container.getTimestamps().get(1).getUniqueId();
    String signatureUniqueId = nestedContainer.getSignatures().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("2", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue(timestamp1UniqueId,"/SimpleReport/TimestampToken[1]/UniqueId", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken[1]/Indication", report);
    TestAssert.assertXPathHasValue("2024-03-27T12:42:57Z", "/SimpleReport/TimestampToken[1]/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.DEMO_SK_TSA_2023E_CN, "/SimpleReport/TimestampToken[1]/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken[1]/TimestampLevel", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken[1]/TimestampScope)", report);
    TestAssert.assertXPathHasValue("valid-bdoc-tm.bdoc", "/SimpleReport/TimestampToken[1]/TimestampScope/@name", report);
    TestAssert.assertXPathHasValue(timestamp2UniqueId,"/SimpleReport/TimestampToken[2]/UniqueId", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken[2]/Indication", report);
    TestAssert.assertXPathHasValue("2024-08-26T13:31:34Z", "/SimpleReport/TimestampToken[2]/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.DEMO_SK_TSA_2023R_CN, "/SimpleReport/TimestampToken[2]/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken[2]/TimestampLevel", report);
    TestAssert.assertXPathHasValue("3", "count(/SimpleReport/TimestampToken[2]/TimestampScope)", report);
    TestAssert.assertXPathHasValue("META-INF/ASiCArchiveManifest.xml", "/SimpleReport/TimestampToken[2]/TimestampScope[1]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/timestamp.tst", "/SimpleReport/TimestampToken[2]/TimestampScope[2]/@name", report);
    TestAssert.assertXPathHasValue("valid-bdoc-tm.bdoc", "/SimpleReport/TimestampToken[2]/TimestampScope[3]/@name", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT-TM", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001016970", "/SimpleReport/Signature/SignedBy", report);
    TestAssert.assertXPathHasValue("TOTAL_PASSED", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("QESig", "/SimpleReport/Signature/SignatureLevel", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void invalidTimestampedContainerWithNestedValidBdoc() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/invalid-containers/1xTST-valid-bdoc-data-file-hash-failure-in-tst.asics");
    Container nestedContainer = TestDataBuilderUtil.open(container.getDataFiles().get(0));
    String timestampUniqueId = container.getTimestamps().get(0).getUniqueId();
    String signatureUniqueId = nestedContainer.getSignatures().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue(timestampUniqueId,"/SimpleReport/TimestampToken[1]/UniqueId", report);
    TestAssert.assertXPathHasValue("FAILED", "/SimpleReport/TimestampToken/Indication", report);
    TestAssert.assertXPathHasValue("2024-03-27T12:42:57Z", "/SimpleReport/TimestampToken/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.DEMO_SK_TSA_2023E_CN, "/SimpleReport/TimestampToken/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken/TimestampLevel", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken/TimestampScope)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken/Errors)", report);
    TestAssert.assertXPathHasValue("The time-stamp message imprint is not intact!", "/SimpleReport/TimestampToken/Errors[1]", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue(signatureUniqueId, "/SimpleReport/Signature/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("XAdES-BASELINE-LT-TM", "/SimpleReport/Signature/@SignatureFormat", report);
    TestAssert.assertXPathHasValue("O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001016970", "/SimpleReport/Signature/SignedBy", report);
    TestAssert.assertXPathHasValue("TOTAL_PASSED", "/SimpleReport/Signature/Indication", report);
    TestAssert.assertXPathHasValue("QESig", "/SimpleReport/Signature/SignatureLevel", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void valid3xTimestampedContainerWithNestedValidDdoc() throws Exception {
    // TODO (DD4J-1123): Currently JDigiDoc configuration (for validating DDoc containers and signatures) is
    //  automatically initialized only once per process, and thus is dependent on the order the unit tests are run.
    //  This workaround helps to avoid unit test failures caused by incompatible configuration being loaded.
    ConfigManager.init(Configuration.getInstance().getDDoc4JConfiguration());

    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/3xTST-valid-ddoc-data-file.asics");
    String timestamp1UniqueId = container.getTimestamps().get(0).getUniqueId();
    String timestamp2UniqueId = container.getTimestamps().get(1).getUniqueId();
    String timestamp3UniqueId = container.getTimestamps().get(2).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("3", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue(timestamp1UniqueId,"/SimpleReport/TimestampToken[1]/UniqueId", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken[1]/Indication", report);
    TestAssert.assertXPathHasValue("2024-10-07T06:17:25Z", "/SimpleReport/TimestampToken[1]/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.DEMO_SK_TSA_2023E_CN, "/SimpleReport/TimestampToken[1]/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken[1]/TimestampLevel", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken[1]/TimestampScope)", report);
    TestAssert.assertXPathHasValue("ddoc-valid.ddoc", "/SimpleReport/TimestampToken[1]/TimestampScope/@name", report);
    TestAssert.assertXPathHasValue(timestamp2UniqueId,"/SimpleReport/TimestampToken[2]/UniqueId", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken[2]/Indication", report);
    TestAssert.assertXPathHasValue("2024-10-07T06:19:30Z", "/SimpleReport/TimestampToken[2]/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.DEMO_SK_TSA_2023R_CN, "/SimpleReport/TimestampToken[2]/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken[2]/TimestampLevel", report);
    TestAssert.assertXPathHasValue("3", "count(/SimpleReport/TimestampToken[2]/TimestampScope)", report);
    TestAssert.assertXPathHasValue("META-INF/ASiCArchiveManifest001.xml", "/SimpleReport/TimestampToken[2]/TimestampScope[1]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/timestamp.tst", "/SimpleReport/TimestampToken[2]/TimestampScope[2]/@name", report);
    TestAssert.assertXPathHasValue("ddoc-valid.ddoc", "/SimpleReport/TimestampToken[2]/TimestampScope[3]/@name", report);
    TestAssert.assertXPathHasValue(timestamp3UniqueId,"/SimpleReport/TimestampToken[3]/UniqueId", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken[3]/Indication", report);
    TestAssert.assertXPathHasValue("2024-10-07T06:21:34Z", "/SimpleReport/TimestampToken[3]/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.DEMO_SK_TSA_2023E_CN, "/SimpleReport/TimestampToken[3]/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken[3]/TimestampLevel", report);
    TestAssert.assertXPathHasValue("5", "count(/SimpleReport/TimestampToken[3]/TimestampScope)", report);
    TestAssert.assertXPathHasValue("META-INF/ASiCArchiveManifest.xml", "/SimpleReport/TimestampToken[3]/TimestampScope[1]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/timestamp.tst", "/SimpleReport/TimestampToken[3]/TimestampScope[2]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/timestamp002.tst", "/SimpleReport/TimestampToken[3]/TimestampScope[3]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/ASiCArchiveManifest001.xml", "/SimpleReport/TimestampToken[3]/TimestampScope[4]/@name", report);
    TestAssert.assertXPathHasValue("ddoc-valid.ddoc", "/SimpleReport/TimestampToken[3]/TimestampScope[5]/@name", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/Signature)", report);
  }

  @Test
  public void validTimestampedContainerWithNestedInvalidDdocWithMultipleSignatures() throws Exception {
    String containerPath = "src/test/resources/testFiles/invalid-containers/one-valid-and-multiple-invalid-signatures.ddoc";
    String containerFilename = Paths.get(containerPath).getFileName().toString();
    // TODO (DD4J-1123): Currently JDigiDoc configuration (for validating DDoc containers and signatures) is
    //  automatically initialized only once per process, and thus is dependent on the order the unit tests are run.
    //  This workaround helps to avoid unit test failures caused by incompatible configuration being loaded.
    ConfigManager.init(configuration.getDDoc4JConfiguration());

    Container container = CompositeContainerBuilder.fromContainerFile(containerPath)
            .withConfiguration(configuration).buildTimestamped(timestampBuilder -> {});
    String timestampUniqueId = container.getTimestamps().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue(timestampUniqueId,"/SimpleReport/TimestampToken/*[position()=1][self::UniqueId]", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken/Indication", report);
    TestAssert.assertXPathHasValue(containerFilename, "/SimpleReport/TimestampToken/TimestampScope/@name", report);
    TestAssert.assertXPathHasValue("7", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/Signature)", report);
  }

  @Test
  public void validTimestampedContainerWithExpiredTimestampToken() throws Exception {
    Container container = ContainerOpener.open(
            "src/test/resources/prodFiles/invalid-containers/1xTST-text-data-file-expired-tst.asics",
            Configuration.of(Configuration.Mode.PROD)
    );
    String timestampUniqueId = container.getTimestamps().get(0).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("0", "/SimpleReport/SignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/Signature)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken)", report);
    System.out.println(report);
    TestAssert.assertXPathHasValue(timestampUniqueId,"/SimpleReport/TimestampToken[1]/UniqueId", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken/Indication", report);
    TestAssert.assertXPathHasValue("2017-08-25T09:56:33Z", "/SimpleReport/TimestampToken/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.SK_TSA_CN, "/SimpleReport/TimestampToken/ProducedBy", report);
    TestAssert.assertXPathHasValue("TSA", "/SimpleReport/TimestampToken/TimestampLevel", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken/TimestampScope)", report);
    TestAssert.assertXPathHasValue("Test.txt", "/SimpleReport/TimestampToken/TimestampScope/@name", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken/Errors)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken/Warnings)", report);
    TestAssert.assertXPathHasValue(
            "The certificate is not related to a granted status at time-stamp lowest POE time!",
            "/SimpleReport/TimestampToken/Warnings[1]", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/ContainerWarning)", report);
    TestAssert.assertXPathHasValue(
            "Found a timestamp token not related to granted status. " +
                    "If not yet covered with a fresh timestamp token, this container might become invalid in the future.",
            "/SimpleReport/ContainerWarning[1]", report
    );
  }

  @Test
  public void validTimestampedContainerWithOneInvalidSecondNoCoverageThirdValidTimestampTokens() throws Exception {
    Container container = ContainerOpener.open(
            "src/test/resources/prodFiles/valid-containers/3xTST-text-data-file-1st-tst-invalid-2nd-tst-no-coverage-3rd-tst-valid.asics",
            Configuration.of(Configuration.Mode.PROD)
    );
    String timestamp1UniqueId = container.getTimestamps().get(0).getUniqueId();
    String timestamp2UniqueId = container.getTimestamps().get(1).getUniqueId();
    String timestamp3UniqueId = container.getTimestamps().get(2).getUniqueId();
    String report = container.validate().getReport();
    TestAssert.assertXPathHasValue("3", "count(/SimpleReport/TimestampToken)", report);
    TestAssert.assertXPathHasValue(timestamp1UniqueId,"/SimpleReport/TimestampToken[1]/UniqueId", report);
    TestAssert.assertXPathHasValue("FAILED", "/SimpleReport/TimestampToken[1]/Indication", report);
    TestAssert.assertXPathHasValue("2024-09-13T10:49:58Z", "/SimpleReport/TimestampToken[1]/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.SK_TSA_2024E_CN, "/SimpleReport/TimestampToken[1]/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken[1]/TimestampLevel", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken[1]/TimestampScope)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken[1]/Errors)", report);
    TestAssert.assertXPathHasValue(
            "The time-stamp message imprint is not intact!",
            "/SimpleReport/TimestampToken[1]/Errors[1]", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken[1]/Warnings)", report);
    TestAssert.assertXPathHasValue(timestamp2UniqueId,"/SimpleReport/TimestampToken[2]/UniqueId", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken[2]/Indication", report);
    TestAssert.assertXPathHasValue("2024-09-13T11:20:02Z", "/SimpleReport/TimestampToken[2]/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.SK_TSA_2024E_CN, "/SimpleReport/TimestampToken[2]/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken[2]/TimestampLevel", report);
    TestAssert.assertXPathHasValue("2", "count(/SimpleReport/TimestampToken[2]/TimestampScope)", report);
    TestAssert.assertXPathHasValue("META-INF/ASiCArchiveManifest001.xml", "/SimpleReport/TimestampToken[2]/TimestampScope[1]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/timestamp.tst", "/SimpleReport/TimestampToken[2]/TimestampScope[2]/@name", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken[2]/Errors)", report);
    TestAssert.assertXPathHasValue("1", "count(/SimpleReport/TimestampToken[2]/Warnings)", report);
    TestAssert.assertXPathHasValue(
            "The time-stamp token does not cover container datafile!",
            "/SimpleReport/TimestampToken[2]/Warnings[1]", report);
    TestAssert.assertXPathHasValue(timestamp3UniqueId,"/SimpleReport/TimestampToken[3]/UniqueId", report);
    TestAssert.assertXPathHasValue("PASSED", "/SimpleReport/TimestampToken[3]/Indication", report);
    TestAssert.assertXPathHasValue("2024-10-25T13:25:59Z", "/SimpleReport/TimestampToken[3]/ProductionTime", report);
    TestAssert.assertXPathHasValue(TestConstants.SK_TSA_2024E_CN, "/SimpleReport/TimestampToken[3]/ProducedBy", report);
    TestAssert.assertXPathHasValue("QTSA", "/SimpleReport/TimestampToken[3]/TimestampLevel", report);
    TestAssert.assertXPathHasValue("5", "count(/SimpleReport/TimestampToken[3]/TimestampScope)", report);
    TestAssert.assertXPathHasValue("META-INF/ASiCArchiveManifest.xml", "/SimpleReport/TimestampToken[3]/TimestampScope[1]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/timestamp.tst", "/SimpleReport/TimestampToken[3]/TimestampScope[2]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/timestamp002.tst", "/SimpleReport/TimestampToken[3]/TimestampScope[3]/@name", report);
    TestAssert.assertXPathHasValue("META-INF/ASiCArchiveManifest001.xml", "/SimpleReport/TimestampToken[3]/TimestampScope[4]/@name", report);
    TestAssert.assertXPathHasValue("test.txt", "/SimpleReport/TimestampToken[3]/TimestampScope[5]/@name", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken[3]/Errors)", report);
    TestAssert.assertXPathHasValue("0", "count(/SimpleReport/TimestampToken[3]/Warnings)", report);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
