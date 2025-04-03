/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.ddoc;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.test.util.JreVersionHelper;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.nullValue;
import static org.xmlunit.matchers.CompareMatcher.isIdenticalTo;

public class DDocSignatureValidationResultTest {

  @Test
  public void testFromListHasNoErrorsAndNoWarnings() {
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(new ArrayList<DigiDocException>(), SignedDoc.FORMAT_DIGIDOC_XML);
    Assert.assertTrue(result.isValid());
    Assert.assertEquals(0, result.getErrors().size());
    Assert.assertFalse(result.hasWarnings());
    Assert.assertEquals(0, result.getWarnings().size());
    Assert.assertTrue(result.isValid());
  }

  @Test
  public void testFromListHasErrors() {
    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(exceptions, SignedDoc.FORMAT_DIGIDOC_XML);
    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();
    Assert.assertFalse(result.isValid());
    Assert.assertEquals(2, errors.size());
    Assert.assertFalse(result.hasWarnings());
    Assert.assertEquals(0, warnings.size());
    Assert.assertFalse(result.isValid());
    Assert.assertEquals(DigiDocException.ERR_UNSUPPORTED, errors.get(0).getErrorCode());
    Assert.assertEquals(DigiDocException.ERR_UNSUPPORTED + "test; nested exception is: \n\tjava.lang.Throwable: exception1",
        errors.get(0).getMessage());
    Assert.assertEquals(DigiDocException.ERR_CALCULATE_DIGEST, errors.get(1).getErrorCode());
    Assert.assertEquals(DigiDocException.ERR_CALCULATE_DIGEST + "test2; nested exception is: \n\tjava.lang.Throwable: " +
        "exception2", errors.get(1).getMessage());
  }

  @Test
  public void testFromListHasWarnings() {
    ArrayList<DigiDocException> exceptions = new ArrayList<>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(exceptions, SignedDoc.FORMAT_DIGIDOC_XML);
    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();
    Assert.assertTrue(result.isValid());
    Assert.assertEquals(0, errors.size());
    Assert.assertTrue(result.hasWarnings());
    Assert.assertEquals(2, warnings.size());
    Assert.assertEquals(DigiDocException.ERR_OLD_VER, warnings.get(0).getErrorCode());
    Assert.assertEquals(DigiDocException.ERR_OLD_VER + "test; nested exception is: \n\tjava.lang.Throwable: exception1",
            warnings.get(0).getMessage());
    Assert.assertEquals(DigiDocException.WARN_WEAK_DIGEST, warnings.get(1).getErrorCode());
    Assert.assertEquals(DigiDocException.WARN_WEAK_DIGEST + "test2; nested exception is: \n\tjava.lang.Throwable: " +
        "exception2", warnings.get(1).getMessage());
  }

  @Test
  public void testReportJava8() {
    // TODO (DD4J-993): Remove this after DD4J unit tests are migrated to JUnit5
    //  which has annotations for conditional test execution based on JRE versions.
    Assume.assumeThat(
            "Only run on JDK 8 or lower",
            JreVersionHelper.getCurrentMajorVersionIfAvailable(),
            anyOf(nullValue(), lessThanOrEqualTo(8))
    );

    ArrayList<DigiDocException> exceptions = new ArrayList<>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(exceptions, SignedDoc.FORMAT_DIGIDOC_XML);
    assertThat(result.getReport(), isIdenticalTo(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" +
            "<root>" +
            "<error Code=\"15\" Message=\"15test; nested exception is: &#10;&#9;java.lang.Throwable: exception1\"/>" +
            "<error Code=\"54\" Message=\"54test2; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception2\"/><warning " +
            "Code=\"177\" Message=\"177test; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception1\"/><warning " +
            "Code=\"129\" Message=\"129test2; nested exception is: &#10;&#9;java.lang.Throwable: exception2\"/>" +
            "</root>" +
            "<!--DDoc verification result-->" // TODO (DD4J-1250): this comment should be located before <root> element
    ));
  }

  @Test
  public void testReportJava9Plus() {
    // TODO (DD4J-993): Remove this after DD4J unit tests are migrated to JUnit5
    //  which has annotations for conditional test execution based on JRE versions.
    Assume.assumeThat(
            "Only run on JDKs higher than 8",
            JreVersionHelper.getCurrentMajorVersionIfAvailable(),
            anyOf(nullValue(), greaterThan(8))
    );

    ArrayList<DigiDocException> exceptions = new ArrayList<>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(exceptions, SignedDoc.FORMAT_DIGIDOC_XML);
    assertThat(result.getReport(), isIdenticalTo(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" +
            "<!--DDoc verification result-->" +
            "<root>" +
            "<error Code=\"15\" Message=\"15test; nested exception is: &#10;&#9;java.lang.Throwable: exception1\"/>" +
            "<error Code=\"54\" Message=\"54test2; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception2\"/><warning " +
            "Code=\"177\" Message=\"177test; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception1\"/><warning " +
            "Code=\"129\" Message=\"129test2; nested exception is: &#10;&#9;java.lang.Throwable: exception2\"/>" +
            "</root>"
    ));
  }

}
