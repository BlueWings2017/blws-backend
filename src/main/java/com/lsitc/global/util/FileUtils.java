package com.lsitc.global.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;

@Slf4j
public final class FileUtils extends org.apache.commons.io.FileUtils {

  private static final String COMPRESS_FILENAME = "compressed.zip";

  public static String getExtension(String filename) {
    if (filename.contains(".")) {
      return filename.substring(filename.lastIndexOf(".") + 1);
    } else {
      return "";
    }
  }

  public static File compressFiles(List<File> files) {
    return compressFiles(files, new File(COMPRESS_FILENAME));
  }

  public static File compressFiles(List<File> files, File destination) {
    try (ZipOutputStream zipOutputStream = new ZipOutputStream(
        Files.newOutputStream(FileUtils.getFile(destination).toPath()))) {
      for (File file : files) {
        ZipEntry zipEntry = new ZipEntry(file.getName());
        zipOutputStream.putNextEntry(zipEntry);
        IOUtils.copy(Files.newInputStream(file.toPath()), zipOutputStream);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return getFile(destination);
  }

  public static File compressFile(File source) {
    return compressFile(source, new File(COMPRESS_FILENAME));
  }

  public static File compressFile(File source, File destination) {
    try (ZipOutputStream zipOutputStream = new ZipOutputStream(
        Files.newOutputStream(destination.toPath()))) {
      ZipEntry zipEntry = new ZipEntry(source.getName());
      zipOutputStream.putNextEntry(zipEntry);
      IOUtils.copy(Files.newInputStream(source.toPath()), zipOutputStream);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return getFile(destination);
  }
}
