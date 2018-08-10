package org.digidoc4j.main.xades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.DigestDataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.main.ExecutionCommand;

public class DetachedXadesExecutionContext {

  private final ExecutionCommand command;
  private final CommandLine commandLine;

  private SignatureToken signatureToken;
  private List<DigestDataFile> digestDataFiles = new ArrayList<>();
  private Signature signature;
  private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
  private SignatureProfile profile = SignatureProfile.LT;

  private DetachedXadesExecutionContext(CommandLine commandLine, ExecutionCommand command) {
    this.commandLine = commandLine;
    this.command = command;
  }

  /**
   * @param commandLine command line arguments
   * @param command internal command
   * @return context
   */
  public static DetachedXadesExecutionContext of(CommandLine commandLine, ExecutionCommand command) {
    return new DetachedXadesExecutionContext(commandLine, command);
  }

  public ExecutionCommand getCommand() {
    return command;
  }

  public CommandLine getCommandLine() {
    return commandLine;
  }

  public List<DigestDataFile> getDigestDataFiles() {
    if (digestDataFiles == null || digestDataFiles.size() < 1) {
      throw new DigiDoc4JException("Digest data file(s) not initialized");
    }
    return digestDataFiles;
  }

  public void addDigestDataFile(DigestDataFile digestDataFile) {
    this.digestDataFiles.add(digestDataFile);
  }

  public SignatureToken getSignatureToken() {
    if (signatureToken == null) {
      throw new DigiDoc4JException("Signature token is not initialized");
    }
    return signatureToken;
  }

  public void setSignatureToken(SignatureToken signatureToken) {
    this.signatureToken = signatureToken;
  }

  public Signature getSignature() {
    if (signature == null) {
      throw new DigiDoc4JException("Signature is not initialized");
    }
    return signature;
  }

  public void setSignature(Signature signature) {
    this.signature = signature;
  }

  public DigestAlgorithm getDigestAlgorithm() {
    if (digestAlgorithm == null) {
      throw new DigiDoc4JException("Digest algorithm is not initialized");
    }
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
  }

  public SignatureProfile getProfile() {
    if (profile == null) {
      throw new DigiDoc4JException("Signature profile is not initialized");
    }
    return profile;
  }

  public void setProfile(SignatureProfile profile) {
    this.profile = profile;
  }
}
