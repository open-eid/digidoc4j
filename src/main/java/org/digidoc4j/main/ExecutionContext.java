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

import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.digidoc4j.Container;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Context holder for utility method. All the corresponding properties must be evaluated before final execution step
 *
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class ExecutionContext {

  private final ExecutionCommand command;
  private final CommandLine commandLine;
  private DataToSign dataToSign;
  private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
  private Container container;
  private SignatureToken signatureToken;
  private X509Certificate certificate;
  private byte[] digest;
  private byte[] signature;

  private ExecutionContext(CommandLine commandLine, ExecutionCommand command) {
    this.commandLine = commandLine;
    this.command = command;
  }

  /**
   * @param commandLine command line arguments
   * @return context
   */
  public static ExecutionContext of(CommandLine commandLine) {
    return ExecutionContext.of(commandLine, null);
  }

  /**
   * @param commandLine command line arguments
   * @param command internal command
   * @return context
   */
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

  public X509Certificate getCertificate() {
    if (this.certificate == null) {
      throw new DigiDoc4JException("Certificate is not initialized");
    }
    return this.certificate;
  }

  public void setCertificate(X509Certificate certificate) {
    this.certificate = certificate;
  }

  public DigestAlgorithm getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
  }

  public DataToSign getDataToSign() {
    if (this.dataToSign == null) {
      throw new DigiDoc4JException("Data to sign is not initialized");
    }
    return this.dataToSign;
  }

  public void setDataToSign(DataToSign dataToSign) {
    this.dataToSign = dataToSign;
  }

}
