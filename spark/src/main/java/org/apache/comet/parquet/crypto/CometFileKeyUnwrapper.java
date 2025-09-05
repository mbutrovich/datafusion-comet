/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.comet.parquet.crypto;

import java.util.concurrent.ConcurrentHashMap;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.crypto.keytools.FileKeyUnwrapper;

/**
 * Helper class to access FileKeyUnwrapper from native code via JNI. This class handles the
 * complexity of getting the proper Hadoop Configuration from the current Spark context and creating
 * a properly configured FileKeyUnwrapper.
 */
public class CometFileKeyUnwrapper {

  /**
   * Cache entry containing both Configuration and optional FileKeyUnwrapper. FileKeyUnwrapper is
   * null until lazy instantiation occurs.
   */
  private static class FileDecryptionMetadata {
    final Configuration hadoopConf;
    volatile FileKeyUnwrapper keyUnwrapper;

    FileDecryptionMetadata(Configuration hadoopConf) {
      this.hadoopConf = hadoopConf;
      this.keyUnwrapper = null;
    }

    FileDecryptionMetadata(Configuration hadoopConf, FileKeyUnwrapper keyUnwrapper) {
      this.hadoopConf = hadoopConf;
      this.keyUnwrapper = keyUnwrapper;
    }
  }

  // Combined cache for Configuration and FileKeyUnwrapper instances
  private static final ConcurrentHashMap<String, FileDecryptionMetadata> CACHE =
      new ConcurrentHashMap<>();

  /**
   * Preemptively stores the Hadoop Configuration for a given file path. This method should be
   * called during plan creation when the correct hadoopConf is available.
   *
   * @param filePath The path to the Parquet file
   * @param hadoopConf The Hadoop Configuration to use for this file path
   */
  public static void storeHadoopConf(String filePath, Configuration hadoopConf) {
    CACHE.put(filePath, new FileDecryptionMetadata(hadoopConf));
  }

  /**
   * Gets the decryption key for the given key metadata and file path. This method is called from
   * native Rust code via JNI.
   *
   * @param keyMetadata The key metadata bytes from the Parquet file
   * @param filePath The path to the Parquet file being decrypted
   * @return The decrypted key bytes
   * @throws Exception if key unwrapping fails
   */
  public static byte[] getKey(byte[] keyMetadata, String filePath) throws Exception {

    // Ensure we have an absolute path
    String absoluteFilePath = filePath;
    if (!filePath.startsWith("/")) {
      // If path is not absolute, prepend "/"
      absoluteFilePath = "/" + filePath;
    }

    // Get the cache entry for this file path
    FileDecryptionMetadata cacheEntry = CACHE.get(absoluteFilePath);
    if (cacheEntry == null) {
      throw new RuntimeException(
          "Failed to retrieve stored hadoopConf for path: " + absoluteFilePath);
    }

    // Check if FileKeyUnwrapper is already instantiated
    FileKeyUnwrapper keyUnwrapper = cacheEntry.keyUnwrapper;
    if (keyUnwrapper == null) {
      // Try using reflection to access the package-private constructor
      // Constructor signature: FileKeyUnwrapper(Configuration hadoopConfiguration, Path
      // filePath)
      java.lang.reflect.Constructor<FileKeyUnwrapper> constructor =
          FileKeyUnwrapper.class.getDeclaredConstructor(Configuration.class, Path.class);
      constructor.setAccessible(true);

      Path path = new Path(absoluteFilePath);
      keyUnwrapper = constructor.newInstance(cacheEntry.hadoopConf, path);

      // Update the cache entry with the instantiated FileKeyUnwrapper
      cacheEntry = new FileDecryptionMetadata(cacheEntry.hadoopConf, keyUnwrapper);
      CACHE.put(absoluteFilePath, cacheEntry);
    }

    // Call the getKey method to decrypt the key
    return keyUnwrapper.getKey(keyMetadata);
  }
}
