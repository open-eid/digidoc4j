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

import org.custommonkey.xmlunit.XMLAssert;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Assert;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
  public void testReport() throws IOException, SAXException {
    ArrayList<DigiDocException> exceptions = new ArrayList<>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));
    DDocSignatureValidationResult result = new DDocSignatureValidationResult(exceptions, SignedDoc.FORMAT_DIGIDOC_XML);
    XMLAssert.assertXMLEqual("<?xml version=\"1.0\" encoding=\"UTF-16\"?>" +
            "<!--DDoc verification result-->" +
            "<root>" +
            "<error Code=\"15\" Message=\"15test; nested exception is: &#10;&#9;java.lang.Throwable: exception1\"/>" +
            "<error Code=\"54\" Message=\"54test2; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception2\"/><warning " +
            "Code=\"177\" Message=\"177test; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception1\"/><warning " +
            "Code=\"129\" Message=\"129test2; nested exception is: &#10;&#9;java.lang.Throwable: exception2\"/></root>",
        result.getReport());
  }

}
