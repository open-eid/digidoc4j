package org.digidoc4j.impl.bdoc;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.apache.xml.security.algorithms.JCEMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JCryptoException;
import org.digidoc4j.utils.Helper;

/**
 * Created by Kaarel Raspel on 24/03/17.
 */
public class BDocCryptoRecipient implements Serializable {

  private String encryptionMethodURI;
  private transient Cipher cipher;
  private X509Cert cert;
  private byte[] cryptogram;

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public BDocCryptoRecipient(String encryptionMethodURI, X509Certificate cert, SecretKey key) {
    this(encryptionMethodURI, new X509Cert(cert), key);
  }

  public BDocCryptoRecipient(String encryptionMethodURI, X509Cert cert, SecretKey key) {
    this(encryptionMethodURI, cert, key.getEncoded(), false);
  }

  public BDocCryptoRecipient(String encryptionMethodURI, X509Certificate cert, byte[] input, boolean inputIsCryptogram) {
    this(encryptionMethodURI, new X509Cert(cert), input, inputIsCryptogram);
  }

  public BDocCryptoRecipient(String encryptionMethodURI, X509Cert cert, byte[] input, boolean inputIsCryptogram) {
    this.cert = cert;
    this.encryptionMethodURI = encryptionMethodURI;
    ensureDataCipher();
    this.cryptogram = inputIsCryptogram ? input : encryptInput(input);
  }

  private byte[] encryptInput(byte[] input) {
    PublicKey publicKey = cert.getX509Certificate().getPublicKey();
    try {
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      return cipher.doFinal(input);
    } catch (GeneralSecurityException ex) {
      throw new DigiDoc4JCryptoException("Could not perform key encrypting", ex);
    }
  }

  public byte[] getCryptogram() {
    return cryptogram;
  }

  public String getKeyEncryptionAlgorithm() {
    return JCEMapper.getJCEKeyAlgorithmFromURI(encryptionMethodURI);
  }

  public String getKeyEncryptionAlgorithmURI() {
    return encryptionMethodURI;
  }

  public Cipher getCipher() {
    ensureDataCipher();
    return cipher;
  }

  private void ensureDataCipher() {
    if (this.cipher == null) {
      this.cipher = Helper.getCipherFor(this.encryptionMethodURI);
    }
  }

  public X509Cert getCert() {
    return cert;
  }

  public void updateKey(byte[] newKeyBytes) {
    this.cryptogram = encryptInput(newKeyBytes);
  }

  public void updateKey(Key newKey) {
    updateKey(newKey.getEncoded());
  }
}
