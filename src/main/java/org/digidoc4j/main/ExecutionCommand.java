/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.main;

import java.util.Arrays;
import java.util.List;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public enum ExecutionCommand {

  EXTERNAL_COMPOSE_DIGEST(Arrays.asList(ExecutionOption.EXTERNAL, ExecutionOption.ADD, ExecutionOption.CERTIFICATE, ExecutionOption.DIGEST)),
  EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS11(Arrays.asList(ExecutionOption.EXTERNAL, ExecutionOption.DIGEST, ExecutionOption.PKCS11, ExecutionOption.SIGNAURE)),
  EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS12(Arrays.asList(ExecutionOption.EXTERNAL, ExecutionOption.DIGEST, ExecutionOption.PKCS12, ExecutionOption.SIGNAURE)),
  EXTERNAL_ADD_SIGNATURE(Arrays.asList(ExecutionOption.EXTERNAL, ExecutionOption.IN, ExecutionOption.ADD, ExecutionOption.SIGNAURE));

  List<ExecutionOption> mandatoryOptions;

  ExecutionCommand(List<ExecutionOption> mandatoryOptions) {
    this.mandatoryOptions = mandatoryOptions;
  }

  /*
   * ACCESSORS
   */

  public List<ExecutionOption> getMandatoryOptions() {
    return mandatoryOptions;
  }

}
