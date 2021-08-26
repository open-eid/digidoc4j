package org.digidoc4j.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.function.LongConsumer;
import java.util.zip.ZipInputStream;

/**
 * Closing this wrapper stream does not close the underlying ZipInputStream.
 * It merely calls <code>closeEntry()</code> on the underlying ZipInputStream.
 */
public class ZipEntryInputStream extends InputStream {

  private final ZipInputStream zipInputStream;
  private final LongConsumer inputReadListener;

  public ZipEntryInputStream(ZipInputStream zipInputStream, LongConsumer inputReadListener) {
    this.zipInputStream = zipInputStream;
    this.inputReadListener = inputReadListener;
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
    int valueRead = zipInputStream.read();
    notifyInputRead(valueRead < 0 ? 0L : 1L);
    return valueRead;
  }

  @Override
  public int read(byte[] b) throws IOException {
    int bytesRead = zipInputStream.read(b);
    notifyInputRead(bytesRead < 0 ? 0L : bytesRead);
    return bytesRead;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    int bytesRead = zipInputStream.read(b, off, len);
    notifyInputRead(bytesRead < 0 ? 0L : bytesRead);
    return bytesRead;
  }

  @Override
  public void reset() throws IOException {
    zipInputStream.reset();
  }

  @Override
  public long skip(long n) throws IOException {
    long bytesSkipped = zipInputStream.skip(n);
    notifyInputRead(bytesSkipped);
    return bytesSkipped;
  }

  private void notifyInputRead(long bytesRead) {
    if (inputReadListener != null) {
      inputReadListener.accept(bytesRead);
    }
  }

}
