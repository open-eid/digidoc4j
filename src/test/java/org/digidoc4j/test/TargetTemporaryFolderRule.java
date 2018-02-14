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

import java.io.File;
import java.nio.file.Paths;

import org.junit.rules.TemporaryFolder;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TargetTemporaryFolderRule extends TemporaryFolder {

  private static final File target = new File("target");
  private File temporaryParentFolder;

  public TargetTemporaryFolderRule(String temporaryParentFolderName) {
    super(Paths.get(TargetTemporaryFolderRule.target.getPath(), temporaryParentFolderName).toFile());
    this.temporaryParentFolder = Paths.get(TargetTemporaryFolderRule.target.getPath(), temporaryParentFolderName).toFile();
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() throws Throwable {
    if (!this.temporaryParentFolder.exists()) {
      this.temporaryParentFolder.mkdir();
    }
    this.create();
  }

  @Override
  protected void after() {
    // Do nothing
  }

}
