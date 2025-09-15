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
import org.apache.parquet.crypto.DecryptionKeyRetriever;
import org.apache.parquet.crypto.DecryptionPropertiesFactory;
import org.apache.parquet.crypto.FileDecryptionProperties;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;

/**
 * Helper class to access DecryptionKeyRetriever from native code via JNI. This class handles the
 * complexity of getting the proper Hadoop Configuration from the current Spark context and creating
 * properly configured DecryptionKeyRetriever instances using DecryptionPropertiesFactory.
 */
public class CometFileKeyUnwrapper implements DecryptionKeyRetriever {

  private final DecryptionKeyRetriever keyRetriever;

  // Cache for CometFileKeyUnwrapper instances
  private static final ConcurrentHashMap<String, CometFileKeyUnwrapper> INSTANCE_CACHE =
      new ConcurrentHashMap<>();

  /** Private constructor - use storeInstance to create instances. */
  private CometFileKeyUnwrapper(
      Configuration hadoopConf, String filePath, FileDecryptionProperties decryptionProperties)
      throws Exception {
    // Use the DecryptionKeyRetriever from the FileDecryptionProperties instead of reflection
    this.keyRetriever = decryptionProperties.getKeyRetriever();
  }

  /**
   * Creates and stores a CometFileKeyUnwrapper instance for the given file path. This method should
   * be called during plan creation when both the filePath and hadoopConf are available.
   *
   * @param filePath The path to the Parquet file
   * @param hadoopConf The Hadoop Configuration to use for this file path
   * @throws Exception if instance creation fails
   */
  public static void storeInstance(String filePath, Configuration hadoopConf) throws Exception {
    // Use DecryptionPropertiesFactory.loadFactory to get the factory and then call
    // getFileDecryptionProperties
    DecryptionPropertiesFactory factory = DecryptionPropertiesFactory.loadFactory(hadoopConf);
    Path path = new Path(filePath);
    FileDecryptionProperties decryptionProperties =
        factory.getFileDecryptionProperties(hadoopConf, path);

    CometFileKeyUnwrapper instance =
        new CometFileKeyUnwrapper(hadoopConf, filePath, decryptionProperties);
    INSTANCE_CACHE.put(filePath, instance);
  }

  /**
   * Retrieves the cached CometFileKeyUnwrapper instance for the given file path. The instance
   * should have been previously stored via storeInstance.
   *
   * @param filePath The path to the Parquet file
   * @return The cached CometFileKeyUnwrapper instance
   * @throws Exception if no instance is found for the given path
   */
  public static CometFileKeyUnwrapper getInstance(String filePath) throws Exception {
    CometFileKeyUnwrapper instance = INSTANCE_CACHE.get(filePath);
    if (instance == null) {
      throw new RuntimeException(
          "Failed to retrieve stored CometFileKeyUnwrapper for path: " + filePath);
    }
    return instance;
  }

  /**
   * Implementation of DecryptionKeyRetriever interface. Gets the decryption key for the given key
   * metadata.
   *
   * @param keyMetadata The key metadata bytes from the Parquet file
   * @return The decrypted key bytes
   * @throws ParquetCryptoRuntimeException if key unwrapping fails
   */
  @Override
  public byte[] getKey(byte[] keyMetadata) throws ParquetCryptoRuntimeException {
    try {
      // Delegate to the underlying DecryptionKeyRetriever from DecryptionProperties
      return keyRetriever.getKey(keyMetadata);
    } catch (Exception e) {
      throw new ParquetCryptoRuntimeException("Failed to decrypt key", e);
    }
  }
}
