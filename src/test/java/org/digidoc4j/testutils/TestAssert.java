package org.digidoc4j.testutils;

import java.io.IOException;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.ocsp.SKOnlineOCSPSource;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DSSDocument;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestAssert {

  private static final Configuration TEST_CONFIGURATION = new Configuration(Configuration.Mode.TEST);

  public static void assertOCSPSource(Configuration configuration, SKOnlineOCSPSource source, String userAgentPart) {
    Assert.assertSame(configuration, source.getConfiguration());
    Assert.assertNotNull(source.getDataLoader());
    Assert.assertThat(source.getDataLoader().getUserAgent(), CoreMatchers.containsString(userAgentPart));
  }

  public static void assertXPathHasValue(String expectedValue, String xPathExpression, String xmlInput) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(IOUtils.toInputStream(xmlInput));
    XPathFactory xPathfactory = XPathFactory.newInstance();
    XPath xpath = xPathfactory.newXPath();
    XPathExpression expr = xpath.compile(xPathExpression);
    String evaluate = expr.evaluate(doc);
    Assert.assertEquals(expectedValue, evaluate);
  }

  public static void assertDSSDocumentIsSigned(DSSDocument document) throws IOException {
    Assert.assertNotNull(document);
    byte[] bytes = IOUtils.toByteArray(document.openStream());
    Assert.assertNotNull(bytes);
    Assert.assertTrue(bytes.length > 0);
  }

  public static void assertContainsError(String error, List<DigiDoc4JException> errors) {
    for (DigiDoc4JException e : errors) {
      if (StringUtils.equalsIgnoreCase(error, e.toString())) {
        return;
      }
    }
    Assert.assertFalse(String.format("Expected <%s> was not found", error), true);
  }

  public static void assertSignatureMetadataContainsFileName(BDocSignature signature, String fileName) {
    Assert.assertNotNull(TestAssert.findSignedFile(signature, fileName));
  }

  /*
   * RESTRICTED METHODS
   */

  private static DSSDocument findSignedFile(BDocSignature signature, String fileName) {
    List<DSSDocument> signedFiles = signature.getOrigin().getDssSignature().getDetachedContents();
    for (DSSDocument signedFile : signedFiles) {
      if (fileName.equals(signedFile.getName())) {
        return signedFile;
      }
    }
    return null;
  }

}
