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
import org.apache.spark.TaskContext;

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
        Configuration hadoopConf = getCurrentHadoopConfiguration();
        System.out.println("Hadoop configuration obtained successfully");
        System.out.flush();

        // Create the file path object
        System.out.println("Creating Hadoop Path object...");
        System.out.flush();
        Path path = new Path(filePath);
        System.out.println("Hadoop Path created successfully");
        System.out.flush();

        // Create the FileKeyUnwrapper with the proper configuration
        // Note: FileKeyUnwrapper constructor is package-private, so we need to use reflection
        // or find an alternative approach
        System.out.println("Creating FileKeyUnwrapper via reflection...");
        System.out.flush();

        // Try using reflection to access the package-private constructor
        java.lang.reflect.Constructor<FileKeyUnwrapper> constructor =
            FileKeyUnwrapper.class.getDeclaredConstructor(
                Configuration.class,
                Path.class,
                org.apache.parquet.crypto.keytools.FileKeyMaterialStore.class);
        constructor.setAccessible(true);

        System.out.println("FileKeyUnwrapper constructor obtained, creating instance...");
        System.out.flush();
        keyUnwrapper = constructor.newInstance(hadoopConf, path, null);
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

  /**
   * Clears the FileKeyUnwrapper cache. This can be called when files are no longer needed to free
   * up memory.
   */
  public static void clearCache() {
    UNWRAPPER_CACHE.clear();
    System.out.println("FileKeyUnwrapper cache cleared");
    System.out.flush();
  }

  /** Removes a specific file path from the cache. */
  public static void removeCachedUnwrapper(String filePath) {
    UNWRAPPER_CACHE.remove(filePath);
    System.out.println("Removed cached FileKeyUnwrapper for path: " + filePath);
    System.out.flush();
  }

  /**
   * Gets the current Hadoop Configuration from the Spark context. This configuration should contain
   * all the necessary settings for encryption/decryption including KMS configurations.
   */
  private static Configuration getCurrentHadoopConfiguration() {
    // Try to get from current task context first
    TaskContext taskContext = TaskContext.get();
    if (taskContext != null) {
      // TaskContext doesn't have direct access to SparkContext
      // We need to access it through the partition/stage info
      try {
        // Access SparkContext through reflection or other means
        // For now, let's use a simpler approach
        return getConfigurationFromActiveSparkContext();
      } catch (Exception e) {
        // Fall back to default
      }
    }

    // Try to get active SparkContext
    return getConfigurationFromActiveSparkContext();
  }

  /** Helper method to get Configuration from active SparkContext */
  private static Configuration getConfigurationFromActiveSparkContext() {
    try {
      // Try to get the current SparkContext through SparkSession
      scala.Option<org.apache.spark.sql.SparkSession> sessionOption =
          org.apache.spark.sql.SparkSession.getActiveSession();
      if (sessionOption.isDefined()) {
        org.apache.spark.sql.SparkSession session = sessionOption.get();
        return session.sparkContext().hadoopConfiguration();
      }
    } catch (Exception e) {
      // Ignore and fall back
    }

    // Last resort: return a new Configuration (may not have all settings)
    // This is not ideal but prevents the code from failing
    return new Configuration();
  }
}
