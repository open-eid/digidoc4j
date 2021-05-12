/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.test;

import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.SkDataLoader;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestAssert {

  private static final Logger log = LoggerFactory.getLogger(TestAssert.class);

  public static void assertOCSPSource(Configuration configuration, SKOnlineOCSPSource source, String userAgentPart) {
    Assert.assertSame(configuration, source.getConfiguration());
    Assert.assertNotNull(source.getDataLoader());
    Assert.assertThat(((SkDataLoader) source.getDataLoader()).getUserAgent(), CoreMatchers.containsString(userAgentPart));
  }

  public static void assertXPathHasValue(String expectedValue, String xPathExpression, String xmlInput) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
    Assert.assertEquals("Value at \"" + xPathExpression + "\" should equal to \"" + expectedValue + "\"",
            expectedValue, getXPathValue(xPathExpression, xmlInput));
  }

  public static void assertXPathHasValue(Pattern expectedValue, String xPathExpression, String xmlInput) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
    Assert.assertTrue("Value at \"" + xPathExpression + "\" should match " + expectedValue.pattern(),
            expectedValue.matcher(getXPathValue(xPathExpression, xmlInput)).matches());
  }

  public static void assertDSSDocumentIsSigned(DSSDocument document) throws IOException {
    Assert.assertNotNull(document);
    byte[] bytes = IOUtils.toByteArray(document.openStream());
    Assert.assertNotNull(bytes);
    Assert.assertTrue(bytes.length > 0);
  }

  public static void assertContainsError(String error, List<DigiDoc4JException> errors) {
    for (DigiDoc4JException e : errors) {
      TestAssert.log.info("Exception error message: <{}>", e.toString());
      if (e.toString().contains(error)) {
        return;
      }
    }
    Assert.fail(String.format("Expected <%s> was not found", error));
  }

  public static void assertSignatureMetadataContainsFileName(Signature signature, String fileName) {
    Assert.assertNotNull(TestAssert.findSignedFile(signature, fileName));
  }

  public static void assertContainerIsValid(Container container) {
    Assert.assertTrue("Container is invalid", container.validate().isValid());
  }

  public static void assertContainerIsInvalid(Container container) {
    Assert.assertFalse("Container is valid", container.validate().isValid());
  }

  public static void assertContainerIsOpened(Container container, Container.DocumentType documentType) {
    Assert.assertEquals(documentType.name(), container.getType());
    Assert.assertFalse(container.getDataFiles().isEmpty());
    Assert.assertFalse(container.getSignatures().isEmpty());
  }

  public static void assertFolderContainsFile(String folderName, String fileName) {
    File folder = new File(folderName);
    File file = new File(folder, fileName);
    Assert.assertTrue(String.format("<%s> is not present in dir <%s>", file, StringUtils.join(folder.list(), "/")), file.exists());
  }

  public static void assertSaveAsStream(Container container) throws IOException {
    container.validate();
    TestAssert.assertContainerStream(container.saveAsStream());
  }

  public static void assertSuppressed(Throwable throwable, Class<?> suppressedType, String... suppressedMessages) {
    Throwable[] suppressedList = throwable.getSuppressed();
    Assert.assertNotNull(suppressedList);
    Assert.assertEquals(suppressedMessages.length, suppressedList.length);
    for (int i = 0; i < suppressedMessages.length; ++i) {
      Assert.assertNotNull(suppressedList[i]);
      Assert.assertTrue(suppressedType.isInstance(suppressedList[i]));
      Assert.assertEquals(suppressedMessages[i], suppressedList[i].getMessage());
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private static String getXPathValue(String xPathExpression, String xmlInput) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(IOUtils.toInputStream(xmlInput, "UTF-8"));
    XPathFactory xPathfactory = XPathFactory.newInstance();
    XPath xpath = xPathfactory.newXPath();
    XPathExpression expr = xpath.compile(xPathExpression);
    return expr.evaluate(doc);
  }

  private static DSSDocument findSignedFile(Signature signature, String fileName) {
    XadesSignature origin = ((AsicESignature)signature).getOrigin();
    List<DSSDocument> signedFiles = origin.getDssSignature().getDetachedContents();
    for (DSSDocument signedFile : signedFiles) {
      if (fileName.equals(signedFile.getName())) {
        return signedFile;
      }
    }
    return null;
  }

  private static void assertContainerStream(InputStream stream) throws IOException {
    Assert.assertTrue(IOUtils.toByteArray(stream).length > 0);
  }

}
