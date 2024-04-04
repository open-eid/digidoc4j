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
import org.digidoc4j.ContainerValidationResult;
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
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;

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

  public static void assertContainsError(String expectedError, List<DigiDoc4JException> errors) {
    for (DigiDoc4JException e : errors) {
      TestAssert.log.info("Exception error message: <{}>", e.toString());
      if (e.toString().contains(expectedError)) {
        return;
      }
    }
    Assert.fail(String.format("Expected <%s> was not found", expectedError));
  }

  public static void assertContainsErrors(List<DigiDoc4JException> errors, String... errorsToExpect) {
    if (errorsToExpect.length == 0 || errorListContainsAllExpectedStrings(errors, errorsToExpect)) {
      return;
    }
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("Expected to find errors containing the following strings:");
    for (String expectedError : errorsToExpect) {
      stringBuilder.append(System.lineSeparator()).append('\t').append(expectedError);
    }
    if (errors.size() > 0) {
      stringBuilder.append(System.lineSeparator()).append("Actual errors found (").append(errors.size()).append("):");
      for (DigiDoc4JException exception : errors) {
        stringBuilder.append(System.lineSeparator()).append('\t').append(exception);
      }
    } else {
      stringBuilder.append("No errors found!");
    }
    Assert.fail(stringBuilder.toString());
  }

  public static void assertContainsExactSetOfErrors(List<DigiDoc4JException> errors, String... allExpectedErrors) {
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(errors, allExpectedErrors.length, allExpectedErrors);
  }

  public static void assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(List<DigiDoc4JException> errors, int expectedNumberOfErrors, String... errorsToExpect) {
    if (errors.size() == expectedNumberOfErrors && errorListContainsAllExpectedStrings(errors, errorsToExpect)) {
      return;
    }
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("Expected ").append(expectedNumberOfErrors).append(" errors")
            .append(errors.size() == expectedNumberOfErrors ? " and" : ", but")
            .append(" found ").append(errors.size());
    if (errorsToExpect.length > 0) {
      stringBuilder.append(System.lineSeparator()).append("List of strings expected to be contained in error messages:");
      for (String expectedError : errorsToExpect) {
        stringBuilder.append(System.lineSeparator()).append('\t').append(expectedError);
      }
    }
    if (errors.size() > 0) {
      stringBuilder.append(System.lineSeparator()).append("Actual errors found (").append(errors.size()).append("):");
      for (DigiDoc4JException exception : errors) {
        stringBuilder.append(System.lineSeparator()).append('\t').append(exception);
      }
    }
    Assert.fail(stringBuilder.toString());
  }

  public static void assertContainsError(Class<? extends DigiDoc4JException> expectedErrorType, List<DigiDoc4JException> errors) {
    for (DigiDoc4JException e : errors) {
      if (expectedErrorType.isInstance(e)) {
        return;
      }
    }
    Assert.fail(String.format("Expected <%s> was not found", expectedErrorType.getSimpleName()));
  }

  public static void assertSignatureMetadataContainsFileName(Signature signature, String fileName) {
    Assert.assertNotNull(TestAssert.findSignedFile(signature, fileName));
  }

  public static void assertContainerIsValid(ContainerValidationResult containerValidationResult) {
    if (containerValidationResult.isValid()) {
      assertThat(containerValidationResult.getErrors(), empty());
    } else {
      StringBuilder stringBuilder = new StringBuilder("Container is invalid");
      for (DigiDoc4JException exception : containerValidationResult.getErrors()) {
        stringBuilder.append(System.lineSeparator()).append('\t').append(exception);
      }
      Assert.fail(stringBuilder.toString());
    }
  }

  public static void assertContainerIsValid(Container container) {
    assertContainerIsValid(container.validate());
  }

  public static void assertContainerIsInvalid(ContainerValidationResult containerValidationResult) {
    Assert.assertFalse("Container is valid", containerValidationResult.isValid());
  }

  public static void assertContainerIsInvalid(Container container) {
    assertContainerIsInvalid(container.validate());
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

  public static void assertTimeBetweenNotBeforeAndNow(Date time, Instant notBefore, Duration clockSkew) {
    Instant timeAsInstant = time.toInstant();
    notBefore = notBefore.minus(clockSkew);
    if (timeAsInstant.isBefore(notBefore)) {
      Assert.fail(String.format("Time '%s' is before 'not-before' (%s)", timeAsInstant, notBefore));
    }
    Instant notAfter = Instant.now().plus(clockSkew);
    if (timeAsInstant.isAfter(notAfter)) {
      Assert.fail(String.format("Time '%s' is after 'not-after' (%s)", timeAsInstant, notAfter));
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

  private static boolean errorListContainsAllExpectedStrings(List<DigiDoc4JException> errorList, String... expectedStrings) {
    for (String expectedString : expectedStrings) {
      if (!errorListContainsExpectedString(errorList, expectedString)) {
        return false;
      }
    }
    return true;
  }

  private static boolean errorListContainsExpectedString(List<DigiDoc4JException> errorList, String expectedString) {
    for (DigiDoc4JException error : errorList) {
      if (error != null && error.toString().contains(expectedString)) {
        return true;
      }
    }
    return false;
  }
}
