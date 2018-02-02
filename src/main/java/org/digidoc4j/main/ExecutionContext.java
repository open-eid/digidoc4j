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

import org.apache.commons.cli.CommandLine;
import org.digidoc4j.Container;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class ExecutionContext {

  private final ExecutionCommand command;
  private final CommandLine commandLine;
  private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
  private Container container;
  private SignatureBuilder signatureBuilder;
  private SignatureToken signatureToken;
  private byte[] digest;
  private byte[] signature;

  private ExecutionContext(CommandLine commandLine, ExecutionCommand command) {
    this.commandLine = commandLine;
    this.command = command;
  }

  public static ExecutionContext of(CommandLine commandLine) {
    return ExecutionContext.of(commandLine, null);
  }

  public static ExecutionContext of(CommandLine commandLine, ExecutionCommand command) {
    return new ExecutionContext(commandLine, command);
  }

  /*
   * ACCESSORS
   */

  public CommandLine getCommandLine() {
    return commandLine;
  }

  public ExecutionCommand getCommand() {
    return command;
  }

  public Container getContainer() {
    if (this.container == null) {
      throw new DigiDoc4JException("Container is not initialized");
    }
    return container;
  }

  public void setContainer(Container container) {
    this.container = container;
  }

  public SignatureToken getSignatureToken() {
    if (this.signatureToken == null) {
      throw new DigiDoc4JException("Signature token is not initialized");
    }
    return this.signatureToken;
  }

  public void setSignatureToken(SignatureToken signatureToken) {
    this.signatureToken = signatureToken;
  }

  public SignatureBuilder getSignatureBuilder() {
    if (this.signatureBuilder == null) {
      throw new DigiDoc4JException("Signature builder is not initialized");
    }
    return this.signatureBuilder;
  }

  public void setSignatureBuilder(SignatureBuilder signatureBuilder) {
    this.signatureBuilder = signatureBuilder;
  }

  public byte[] getDigest() {
    if (this.digest == null) {
      throw new DigiDoc4JException("Digest is not initialized");
    }
    return this.digest;
  }

  public void setDigest(byte[] digest) {
    this.digest = digest;
  }

  public byte[] getSignature() {
    if (this.signature == null) {
      throw new DigiDoc4JException("Signature is not initialized");
    }
    return this.signature;
  }

  public void setSignature(byte[] signature) {
    this.signature = signature;
  }

  public DigestAlgorithm getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
  }

}
