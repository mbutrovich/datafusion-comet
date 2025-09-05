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

  // Cache FileKeyUnwrapper instances by file path to reuse KMS configuration
  private static final ConcurrentHashMap<String, FileKeyUnwrapper> UNWRAPPER_CACHE =
      new ConcurrentHashMap<>();

  // Cache mapping from file path to its corresponding Hadoop Configuration
  private static final ConcurrentHashMap<String, Configuration> HADOOP_CONF_CACHE =
      new ConcurrentHashMap<>();

  /**
   * Preemptively stores the Hadoop Configuration for a given file path. This method should be
   * called during plan creation when the correct hadoopConf is available.
   *
   * @param filePath The path to the Parquet file
   * @param hadoopConf The Hadoop Configuration to use for this file path
   */
  public static void storeHadoopConf(String filePath, Configuration hadoopConf) {
    HADOOP_CONF_CACHE.put(filePath, hadoopConf);
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

    try {
      // Try to get cached FileKeyUnwrapper first
      FileKeyUnwrapper keyUnwrapper = UNWRAPPER_CACHE.get(absoluteFilePath);

      if (keyUnwrapper == null) {

        // Get the Hadoop configuration for this file path, or create a default one
        Configuration hadoopConf = HADOOP_CONF_CACHE.get(absoluteFilePath);
        if (hadoopConf == null) {
          throw new RuntimeException(
              "Failed to retrieve stored hadoopConf for path: " + absoluteFilePath);
        }

        // Try using reflection to access the package-private constructor
        // Constructor signature: FileKeyUnwrapper(Configuration hadoopConfiguration, Path filePath)
        java.lang.reflect.Constructor<FileKeyUnwrapper> constructor =
            FileKeyUnwrapper.class.getDeclaredConstructor(Configuration.class, Path.class);
        constructor.setAccessible(true);

        Path path = new Path(absoluteFilePath);
        keyUnwrapper = constructor.newInstance(hadoopConf, path);

        // Cache the instance for future use
        UNWRAPPER_CACHE.put(absoluteFilePath, keyUnwrapper);
      }

      // Call the getKey method to decrypt the key
      return keyUnwrapper.getKey(keyMetadata);
    } catch (Exception e) {
      System.err.println(
          "Exception in CometFileKeyUnwrapper.getKey: "
              + e.getClass().getSimpleName()
              + ": "
              + e.getMessage());
      e.printStackTrace();
      System.err.flush();
      throw new RuntimeException("Failed to decrypt key: " + e.getMessage(), e);
    }
  }
}
