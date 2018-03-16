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

import org.digidoc4j.DataFile;

import eu.europa.esig.dss.InMemoryDocument;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class MockDataFile extends DataFile {

  public MockDataFile(byte[] data, String fileName, String mimeType) {
    super(data, fileName, mimeType);
    this.setDocument(new InMemoryDocument(data, mimeType));
  }

}
