package com.lsitc.global.filter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class ReadableHttpServletRequestWrapper extends HttpServletRequestWrapper {
  private byte[] bytes;

  public ReadableHttpServletRequestWrapper(HttpServletRequest request) throws IOException {
    super(request);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    super.getInputStream().transferTo(baos);
    this.bytes = baos.toByteArray();
  }

  @Override
  public ServletInputStream getInputStream() throws IOException {
    return new CustomServletInputStream(bytes);
  }

  @Override
  public BufferedReader getReader() throws IOException {
    return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(this.bytes)));
  }

  public byte[] getContentAsByteArray() {
    return this.bytes;
  }

  private class CustomServletInputStream extends ServletInputStream {

    private final InputStream delegate;

    public CustomServletInputStream(byte[] body) {
      this.delegate = new ByteArrayInputStream(body);
    }

    @Override
    public boolean isFinished() {
      return false;
    }

    @Override
    public boolean isReady() {
      return true;
    }

    @Override
    public void setReadListener(ReadListener readListener) {
      throw new UnsupportedOperationException();
    }

    @Override
    public int read() throws IOException {
      return this.delegate.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      return this.delegate.read(b, off, len);
    }

    @Override
    public int read(byte[] b) throws IOException {
      return this.delegate.read(b);
    }

    @Override
    public long skip(long n) throws IOException {
      return this.delegate.skip(n);
    }

    @Override
    public int available() throws IOException {
      return this.delegate.available();
    }

    @Override
    public void close() throws IOException {
      this.delegate.close();
    }

    @Override
    public synchronized void mark(int readlimit) {
      this.delegate.mark(readlimit);
    }

    @Override
    public synchronized void reset() throws IOException {
      this.delegate.reset();
    }

    @Override
    public boolean markSupported() {
      return this.delegate.markSupported();
    }
  }

}
