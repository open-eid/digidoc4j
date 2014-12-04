/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;

import ee.sk.digidoc.DigiDocException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;
import static org.junit.Assert.*;

public class ValidationResultForDDocTest {

  @Test
  public void testFromListHasNoErrorsAndNoWarnings() {
    ValidationResultForDDoc result = new ValidationResultForDDoc(new ArrayList<DigiDocException>());

    assertFalse(result.hasErrors());
    assertEquals(0, result.getErrors().size());

    assertFalse(result.hasWarnings());
    assertEquals(0, result.getWarnings().size());

    assertTrue(result.isValid());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromListHasErrors() {
    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));

    ValidationResultForDDoc result = new ValidationResultForDDoc(exceptions);
    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();

    assertTrue(result.hasErrors());
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

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void testFromListHasWarnings() {
    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));

    ValidationResultForDDoc result = new ValidationResultForDDoc(exceptions);
    List<DigiDoc4JException> errors = result.getErrors();
    List<DigiDoc4JException> warnings = result.getWarnings();

    assertTrue(result.hasErrors());
    assertEquals(2, errors.size());

    assertFalse(result.hasWarnings());
    assertEquals(0, warnings.size());

    assertFalse(result.isValid());

    assertEquals(DigiDocException.ERR_OLD_VER, errors.get(0).getErrorCode());
    assertEquals(DigiDocException.ERR_OLD_VER + "test; nested exception is: \n\tjava.lang.Throwable: exception1",
        errors.get(0).getMessage());

    assertEquals(DigiDocException.WARN_WEAK_DIGEST, errors.get(1).getErrorCode());
    assertEquals(DigiDocException.WARN_WEAK_DIGEST + "test2; nested exception is: \n\tjava.lang.Throwable: " +
        "exception2", errors.get(1).getMessage());
  }

  @Test
  public void testReport() throws IOException, SAXException {
    ArrayList<DigiDocException> exceptions = new ArrayList<DigiDocException>();
    exceptions.add(new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.ERR_CALCULATE_DIGEST, "test2", new Throwable("exception2")));

    exceptions.add(new DigiDocException(DigiDocException.ERR_OLD_VER, "test", new Throwable("exception1")));
    exceptions.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, "test2", new Throwable("exception2")));

    ValidationResultForDDoc result = new ValidationResultForDDoc(exceptions);
    assertXMLEqual("<?xml version=\"1.0\" encoding=\"UTF-16\"?>" +
            "<!--DDoc verification result-->" +
            "<root>" +
            "<error Code=\"15\" Message=\"15test; nested exception is: &#10;&#9;java.lang.Throwable: exception1\"/>" +
            "<error Code=\"54\" Message=\"54test2; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception2\"/><error " +
            "Code=\"177\" Message=\"177test; nested exception is: &#10;&#9;java.lang.Throwable: " +
            "exception1\"/><error " +
            "Code=\"129\" Message=\"129test2; nested exception is: &#10;&#9;java.lang.Throwable: exception2\"/></root>",
        result.getReport());
    System.out.println();
  }

}
