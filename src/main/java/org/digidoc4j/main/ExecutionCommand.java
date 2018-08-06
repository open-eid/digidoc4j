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
 * Internal command wrapper which defines possible combinations of mandatory execution arguments. All the arguments will
 * be executed in the order they are defined in the array of argument options
 * <p>
 * Created by Janar Rahumeel (CGI Estonia)
 */

public enum ExecutionCommand {

  EXTERNAL_COMPOSE_DTS(
      Arrays.asList(ExecutionOption.IN, ExecutionOption.ADD, ExecutionOption.CERTIFICATE, ExecutionOption.DTS)),
  EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS11(
      Arrays.asList(ExecutionOption.DTS, ExecutionOption.PKCS11, ExecutionOption.SIGNATURE)),
  EXTERNAL_COMPOSE_SIGNATURE_WITH_PKCS12(
      Arrays.asList(ExecutionOption.DTS, ExecutionOption.PKCS12, ExecutionOption.SIGNATURE)),
  EXTERNAL_ADD_SIGNATURE(Arrays.asList(ExecutionOption.IN, ExecutionOption.DTS, ExecutionOption.SIGNATURE)),

  XADES_COMPOSE_SIGNATURE_WITH_PKCS11(
      Arrays.asList(ExecutionOption.DETACHED_XADES, ExecutionOption.DIGEST_FILE, ExecutionOption.PKCS11,
          ExecutionOption.XADES_OUTPUT_PATH)),
  XADES_COMPOSE_SIGNATURE_WITH_PKCS12(
      Arrays.asList(ExecutionOption.DETACHED_XADES, ExecutionOption.DIGEST_FILE, ExecutionOption.PKCS12,
          ExecutionOption.XADES_OUTPUT_PATH)),
  XADES_LOAD_SIGNATURE(
      Arrays.asList(ExecutionOption.DETACHED_XADES, ExecutionOption.DIGEST_FILE, ExecutionOption.XADES_INPUT_PATH));

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
