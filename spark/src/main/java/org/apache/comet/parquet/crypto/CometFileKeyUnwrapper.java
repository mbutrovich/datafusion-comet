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

  private final FileKeyUnwrapper keyUnwrapper;

  // Cache for Configuration instances - still needed for compatibility
  private static final ConcurrentHashMap<String, Configuration> HADOOP_CONF_CACHE =
      new ConcurrentHashMap<>();

  /** Private constructor - use createInstance to create instances. */
  private CometFileKeyUnwrapper(Configuration hadoopConf, String filePath) throws Exception {

    // Try using reflection to access the package-private constructor
    // Constructor signature: FileKeyUnwrapper(Configuration hadoopConfiguration, Path filePath)
    java.lang.reflect.Constructor<FileKeyUnwrapper> constructor =
        FileKeyUnwrapper.class.getDeclaredConstructor(Configuration.class, Path.class);
    constructor.setAccessible(true);

    Path path = new Path(filePath);
    this.keyUnwrapper = constructor.newInstance(hadoopConf, path);
  }

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
   * Creates a new CometFileKeyUnwrapper instance for the given file path. The Hadoop Configuration
   * should have been previously stored via storeHadoopConf.
   *
   * @param filePath The path to the Parquet file
   * @return A new CometFileKeyUnwrapper instance
   * @throws Exception if instance creation fails
   */
  public static CometFileKeyUnwrapper createInstance(String filePath) throws Exception {

    // Get the cached Hadoop Configuration for this file path
    Configuration hadoopConf = HADOOP_CONF_CACHE.get(filePath);
    if (hadoopConf == null) {
      throw new RuntimeException("Failed to retrieve stored hadoopConf for path: " + filePath);
    }

    return new CometFileKeyUnwrapper(hadoopConf, filePath);
  }

  /**
   * Gets the decryption key for the given key metadata.
   *
   * @param keyMetadata The key metadata bytes from the Parquet file
   * @return The decrypted key bytes
   * @throws Exception if key unwrapping fails
   */
  public byte[] getKey(byte[] keyMetadata) throws Exception {
    // Call the getKey method to decrypt the key
    return keyUnwrapper.getKey(keyMetadata);
  }
}
