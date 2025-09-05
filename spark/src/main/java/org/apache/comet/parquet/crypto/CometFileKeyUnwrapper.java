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
    System.out.println("CometFileKeyUnwrapper.getKey called with filePath: " + filePath);
    System.out.println("CometFileKeyUnwrapper.getKey keyMetadata length: " + keyMetadata.length);
    System.out.flush();

    try {
      // Try to get cached FileKeyUnwrapper first
      FileKeyUnwrapper keyUnwrapper = UNWRAPPER_CACHE.get(filePath);

      if (keyUnwrapper == null) {
        System.out.println("No cached FileKeyUnwrapper found for path, creating new instance...");
        System.out.flush();

        // Get the current Spark context's Hadoop configuration
        System.out.println("Getting Hadoop configuration...");
        System.out.flush();
        Configuration hadoopConf = new Configuration();
        System.out.println("Hadoop configuration obtained successfully");
        System.out.flush();

        // Create the file path object
        System.out.println("Creating Hadoop Path object...");
        System.out.flush();

        // Ensure we have an absolute path
        String absoluteFilePath = filePath;
        if (!filePath.startsWith("/")) {
          // If path is not absolute, prepend "/"
          absoluteFilePath = "/" + filePath;
          System.out.println("Converted relative path to absolute: " + absoluteFilePath);
          System.out.flush();
        }

        Path path = new Path(absoluteFilePath);
        System.out.println("Hadoop Path created successfully: " + path.toString());
        System.out.flush();

        // Create the FileKeyUnwrapper with the proper configuration
        // FileKeyUnwrapper constructor: FileKeyUnwrapper(Configuration hadoopConfiguration, Path
        // filePath)
        System.out.println("Creating FileKeyUnwrapper via reflection...");
        System.out.flush();

        // Debug: Print relevant configuration properties
        System.out.println("Hadoop Configuration properties:");
        System.out.println(
            "  parquet.encryption.kms.client.class: "
                + hadoopConf.get("parquet.encryption.kms.client.class"));
        System.out.println(
            "  parquet.encryption.kms.instance.id: "
                + hadoopConf.get("parquet.encryption.kms.instance.id"));
        System.out.println(
            "  parquet.encryption.kms.instance.url: "
                + hadoopConf.get("parquet.encryption.kms.instance.url"));
        System.out.println(
            "  parquet.encryption.key.list: " + hadoopConf.get("parquet.encryption.key.list"));
        System.out.flush();

        // Try using reflection to access the package-private constructor
        // Constructor signature: FileKeyUnwrapper(Configuration hadoopConfiguration, Path filePath)
        java.lang.reflect.Constructor<FileKeyUnwrapper> constructor =
            FileKeyUnwrapper.class.getDeclaredConstructor(Configuration.class, Path.class);
        constructor.setAccessible(true);

        System.out.println("FileKeyUnwrapper constructor obtained, creating instance...");
        System.out.flush();
        keyUnwrapper = constructor.newInstance(hadoopConf, path);
        System.out.println("FileKeyUnwrapper instance created successfully");
        System.out.flush();

        // Cache the instance for future use
        UNWRAPPER_CACHE.put(filePath, keyUnwrapper);
        System.out.println("FileKeyUnwrapper cached for path: " + filePath);
        System.out.flush();
      } else {
        System.out.println("Using cached FileKeyUnwrapper for path: " + filePath);
        System.out.flush();
      }

      // Call the getKey method to decrypt the key
      System.out.println("Calling FileKeyUnwrapper.getKey...");
      System.out.flush();
      byte[] result = keyUnwrapper.getKey(keyMetadata);
      System.out.println(
          "FileKeyUnwrapper.getKey completed successfully, result length: "
              + (result != null ? result.length : "null"));
      System.out.flush();

      return result;
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
