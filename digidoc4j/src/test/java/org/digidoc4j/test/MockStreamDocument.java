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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.impl.StreamDocument;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class MockStreamDocument  extends StreamDocument {

  public MockStreamDocument() {
    super(new ByteArrayInputStream(new byte[]{0x041}), "fileName.txt", MimeTypeEnum.TEXT);
  }

  @Override
  protected FileInputStream getTemporaryFileAsStream() throws FileNotFoundException {
    throw new FileNotFoundException("File not found (mock)");
  }

}
