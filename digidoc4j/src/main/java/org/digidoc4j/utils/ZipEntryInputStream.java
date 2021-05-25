package org.digidoc4j.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipInputStream;

/**
 * Closing this wrapper stream does not close the underlying ZipInputStream.
 * It merely calls <code>closeEntry()</code> on the underlying ZipInputStream.
 */
public class ZipEntryInputStream extends InputStream {

  private final ZipInputStream zipInputStream;
  private final ThrowingConsumer<Integer, IOException> validator;
  private int counter;

  public ZipEntryInputStream(ZipInputStream zipInputStream, ThrowingConsumer<Integer, IOException> validator) {
    this.zipInputStream = zipInputStream;
    this.validator = validator;
  }

  @Override
  public int available() throws IOException {
    return zipInputStream.available();
  }

  @Override
  public void close() throws IOException {
    zipInputStream.closeEntry();
  }

  @Override
  public void mark(int readlimit) {
    zipInputStream.mark(readlimit);
  }

  @Override
  public boolean markSupported() {
    return zipInputStream.markSupported();
  }

  @Override
  public int read() throws IOException {
    int result = zipInputStream.read();
    checkEntry(result);
    return result;
  }

  @Override
  public int read(byte[] b) throws IOException {
    int result = zipInputStream.read(b);
    checkEntry(result);
    return result;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    int result = zipInputStream.read(b, off, len);
    checkEntry(result);
    return result;
  }

  @Override
  public void reset() throws IOException {
    zipInputStream.reset();
  }

  @Override
  public long skip(long n) throws IOException {
    return zipInputStream.skip(n);
  }

  private void checkEntry(int result) throws IOException {
    if (validator != null) {
      counter += result;
      validator.accept(counter);
    }
  }

  @FunctionalInterface
  public interface ThrowingConsumer<T, E extends Exception> {
    void accept(T t) throws E;
  }

}
