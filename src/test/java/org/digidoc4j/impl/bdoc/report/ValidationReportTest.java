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

import static org.digidoc4j.testutils.TestDataBuilder.createContainerWithFile;
import static org.digidoc4j.testutils.TestDataBuilder.signContainer;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.MimeType;

public class ValidationReportTest extends DigiDoc4JTestHelper {

  @Test
  public void validContainerWithOneSignature() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt");
    Signature signature = TestDataBuilder.signContainer(container, SignatureProfile.LT);
    String signatureId = signature.getId();
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
    String report = result.getReport();
    assertXpathHasValue("1", "//SignaturesCount", report);
    assertXpathHasValue("1", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    assertXpathHasValue(signatureId, "/SimpleReport/Signature/@Id", report);
    assertXpathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature/@SignatureFormat", report);
    //assertXpathHasValue("QES", "/SimpleReport/Signature[@Id='" + signatureId + "']/SignatureLevel", report);
    assertXpathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature[@Id='" + signatureId + "']/SignedBy", report);
    assertXpathHasValue("TOTAL_PASSED", "/SimpleReport/Signature[@Id='" + signatureId + "']/Indication", report);
    assertXpathHasValue("Full document", "/SimpleReport/Signature[@Id='" + signatureId + "']/SignatureScope", report);
    assertXpathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
    assertXpathHasValue("", "/SimpleReport/Signature[@Id='" + signatureId + "']/Errors", report);
  }

  @Test
  public void validContainerWithOneTmSignature() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt");
    container.addDataFile("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf", MimeType.PDF.getMimeTypeString());
    signContainer(container, SignatureProfile.LT_TM);
    ValidationResult result = container.validate();
    String report = result.getReport();
    System.out.println(result.getReport());
    assertXpathHasValue("1", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("1", "/SimpleReport/ValidSignaturesCount", report);
    assertXpathHasValue("XAdES_BASELINE_LT_TM", "/SimpleReport/Signature/@SignatureFormat", report);
    //assertXpathHasValue("QES", "/SimpleReport/Signature/SignatureLevel", report);
    assertXpathHasValue("TOTAL_PASSED", "/SimpleReport/Signature/Indication", report);
    assertXpathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope[1]/@name", report);
    assertXpathHasValue("dds_acrobat.pdf", "/SimpleReport/Signature/SignatureScope[2]/@name", report);
  }

  @Test
  public void containerWithOneBesSignature() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt");
    signContainer(container, SignatureProfile.B_BES);
    ValidationResult result = container.validate();
    String report = result.getReport();
    assertXpathHasValue("1", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    assertXpathHasValue("XAdES-BASELINE-B", "/SimpleReport/Signature/@SignatureFormat", report);
    //assertXpathHasValue("QES", "/SimpleReport/Signature/SignatureLevel", report);
    assertXpathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    assertXpathHasValue("TRY_LATER", "/SimpleReport/Signature/SubIndication", report);
    assertXpathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void containerWithOneEpesSignature() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt");
    signContainer(container, SignatureProfile.B_EPES);
    ValidationResult result = container.validate();
    String report = result.getReport();
    assertXpathHasValue("1", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    assertXpathHasValue("XAdES_BASELINE_B_EPES", "/SimpleReport/Signature/@SignatureFormat", report);
    //assertXpathHasValue("QES", "/SimpleReport/Signature/SignatureLevel", report);
    assertXpathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    assertXpathHasValue("TRY_LATER", "/SimpleReport/Signature/SubIndication", report);
    assertXpathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void validContainerWithTwoSignatures() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt");
    Signature signature1 = signContainer(container, SignatureProfile.LT_TM);
    Signature signature2 = signContainer(container, SignatureProfile.LT);
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
    String report = result.getReport();
    assertXpathHasValue("2", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("2", "/SimpleReport/ValidSignaturesCount", report);
    assertXpathHasValue(signature1.getId(), "/SimpleReport/Signature[1]/@Id", report);
    assertXpathHasValue(signature2.getId(), "/SimpleReport/Signature[2]/@Id", report);
    assertXpathHasValue("XAdES_BASELINE_LT_TM", "/SimpleReport/Signature[1]/@SignatureFormat", report);
    assertXpathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature[2]/@SignatureFormat", report);
    assertXpathHasValue("test.txt", "/SimpleReport/Signature[1]/SignatureScope/@name", report);
    assertXpathHasValue("test.txt", "/SimpleReport/Signature[2]/SignatureScope/@name", report);
  }

  @Test
  public void invalidContainerWithOneSignature() throws Exception {
    Container container = TestDataBuilder.open("src/test/resources/testFiles/invalid-containers/bdoc-tm-ocsp-revoked.bdoc");
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    String report = result.getReport();
    assertXpathHasValue("1", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    assertXpathHasValue("XAdES_BASELINE_LT_TM", "/SimpleReport/Signature/@SignatureFormat", report);
    //assertXpathHasValue("QES", "/SimpleReport/Signature/SignatureLevel", report);
    assertXpathHasValue("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", "/SimpleReport/Signature/SignedBy", report);
    assertXpathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    assertXpathHasValue("NO_POE", "/SimpleReport/Signature/SubIndication", report);
    assertXpathHasValue("The past signature validation is not conclusive!", "/SimpleReport/Signature/Errors", report);
    assertXpathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    assertXpathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  @Test
  public void invalidContainerWithManifestErrors() throws Exception {
    Container container = TestDataBuilder.open("src/test/resources/testFiles/invalid-containers/filename_mismatch_manifest.asice");
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    String report = result.getReport();
    assertXpathHasValue("1", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    assertXpathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature/@SignatureFormat", report);
    //assertXpathHasValue("AdESqc", "/SimpleReport/Signature/SignatureLevel", report);
    assertXpathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    assertXpathHasValue("NO_CERTIFICATE_CHAIN_FOUND", "/SimpleReport/Signature/SubIndication", report);
    assertXpathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    assertXpathHasValue("RELEASE-NOTES.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
    assertXpathHasValue("The certificate chain for signature is not trusted, there is no trusted anchor.", "/SimpleReport/Signature/Errors", report);
    assertXpathHasValue("Manifest file has an entry for file incorrect.txt with mimetype text/plain but the signature file for signature S0 does not have an entry for this file", "/SimpleReport/ContainerError[1]", report);
    assertXpathHasValue("The signature file for signature S0 has an entry for file RELEASE-NOTES.txt with mimetype text/plain but the manifest file does not have an entry for this file", "/SimpleReport/ContainerError[2]", report);
  }

  @Test
  public void containerWithoutSignatures() throws Exception {
    Container container = TestDataBuilder.open("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    ValidationResult result = container.validate();
    String report = result.getReport();
    assertXpathHasValue("0", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
  }

  @Test
  public void signatureContainsAdditionalErrors() throws Exception {
    Container container = TestDataBuilder.open("src/test/resources/testFiles/invalid-containers/TS-08_23634_TS_OCSP_before_TS.asice");
    ValidationResult result = container.validate();
    String report = result.getReport();
    assertXpathHasValue("1", "/SimpleReport/SignaturesCount", report);
    assertXpathHasValue("0", "/SimpleReport/ValidSignaturesCount", report);
    assertXpathHasValue("XAdES-BASELINE-LT", "/SimpleReport/Signature/@SignatureFormat", report);
    //assertXpathHasValue("QES", "/SimpleReport/Signature/SignatureLevel", report);
    assertXpathHasValue("ŽAIKOVSKI,IGOR,37101010021", "/SimpleReport/Signature/SignedBy", report);
    assertXpathHasValue("INDETERMINATE", "/SimpleReport/Signature/Indication", report);
    assertXpathHasValue("Signature has an invalid timestamp", "/SimpleReport/Signature/Errors[1]", report);
    assertXpathHasValue("META-INF/signatures0.xml", "/SimpleReport/Signature/DocumentName", report);
    assertXpathHasValue("test.txt", "/SimpleReport/Signature/SignatureScope/@name", report);
  }

  private void assertXpathHasValue(String expectedValue, String xPathExpression, String xmlInput) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(IOUtils.toInputStream(xmlInput));
    XPathFactory xPathfactory = XPathFactory.newInstance();
    XPath xpath = xPathfactory.newXPath();
    XPathExpression expr = xpath.compile(xPathExpression);
    String evaluate = expr.evaluate(doc);
    assertEquals(expectedValue, evaluate);
  }
}
