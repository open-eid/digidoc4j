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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnJre;
import org.junit.jupiter.api.condition.EnabledOnJre;
import org.junit.jupiter.api.condition.JRE;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.xmlunit.matchers.CompareMatcher.isIdenticalTo;

class DDocSignatureValidationResultTest {

  @Test
  void testFromListHasNoErrorsAndNoWarnings() {
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(new ArrayList<DigiDocException>(), SignedDoc.FORMAT_DIGIDOC_XML);
    assertTrue(result.isValid());
    assertEquals(0, result.getErrors().size());
    assertFalse(result.hasWarnings());
    assertEquals(0, result.getWarnings().size());
    assertTrue(result.isValid());
  }

  @Test
  void testFromListHasErrors() {
    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(exceptions, SignedDoc.FORMAT_DIGIDOC_XML);
    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();
    assertFalse(result.isValid());
    assertEquals(2, errors.size());
    assertFalse(result.hasWarnings());
    assertEquals(0, warnings.size());
    assertFalse(result.isValid());
    assertEquals(DigiDocException.ERR_UNSUPPORTED, errors.get(0).getErrorCode());
    assertEquals(DigiDocException.ERR_UNSUPPORTED + "test; nested exception is: \n\tjava.lang.Throwable: exception1",
        errors.get(0).getMessage());
    assertEquals(DigiDocException.ERR_CALCULATE_DIGEST, errors.get(1).getErrorCode());
    assertEquals(DigiDocException.ERR_CALCULATE_DIGEST + "test2; nested exception is: \n\tjava.lang.Throwable: " +
        "exception2", errors.get(1).getMessage());
  }

  @Test
  void testFromListHasWarnings() {
    ArrayList<DigiDocException> exceptions = new ArrayList<>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(exceptions, SignedDoc.FORMAT_DIGIDOC_XML);
    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();
    assertTrue(result.isValid());
    assertEquals(0, errors.size());
    assertTrue(result.hasWarnings());
    assertEquals(2, warnings.size());
    assertEquals(DigiDocException.ERR_OLD_VER, warnings.get(0).getErrorCode());
    assertEquals(DigiDocException.ERR_OLD_VER + "test; nested exception is: \n\tjava.lang.Throwable: exception1",
            warnings.get(0).getMessage());
    assertEquals(DigiDocException.WARN_WEAK_DIGEST, warnings.get(1).getErrorCode());
    assertEquals(DigiDocException.WARN_WEAK_DIGEST + "test2; nested exception is: \n\tjava.lang.Throwable: " +
        "exception2", warnings.get(1).getMessage());
  }

  @EnabledOnJre(JRE.JAVA_8)
  @Test
  void testReportJava8() {
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

  @DisabledOnJre(JRE.JAVA_8)
  @Test
  void testReportJava9Plus() {
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
