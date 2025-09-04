// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use jni::{
    errors::Result as JniResult,
    objects::{JClass, JStaticMethodID},
    signature::ReturnType,
    JNIEnv,
};
use std::io::{self, Write};

/// A struct that holds all the JNI methods and fields for JVM FileKeyUnwrapper object.
pub struct FileKeyUnwrapper<'a> {
    pub class: JClass<'a>,
    pub method_get_key: JStaticMethodID,
    pub method_get_key_ret: ReturnType,
}

impl<'a> FileKeyUnwrapper<'a> {
    pub const JVM_CLASS: &'static str = "org/apache/comet/parquet/crypto/CometFileKeyUnwrapper";

    pub fn new(env: &mut JNIEnv<'a>) -> JniResult<FileKeyUnwrapper<'a>> {
        println!("FileKeyUnwrapper::new - attempting to find class: {}", Self::JVM_CLASS);
        io::stdout().flush().expect("Failed to flush stdout");
        
        let class = match env.find_class(Self::JVM_CLASS) {
            Ok(cls) => {
                println!("FileKeyUnwrapper::new - class found successfully");
                io::stdout().flush().expect("Failed to flush stdout");
                cls
            },
            Err(e) => {
                println!("FileKeyUnwrapper::new - failed to find class: {}", e);
                io::stdout().flush().expect("Failed to flush stdout");
                return Err(e);
            }
        };

        // getKey is a static method with signature: public static byte[] getKey(byte[] keyMetadata, String filePath)
        println!("FileKeyUnwrapper::new - attempting to get static method ID for getKey([BLjava/lang/String;)[B");
        io::stdout().flush().expect("Failed to flush stdout");
        
        let method_get_key = match env.get_static_method_id(
            Self::JVM_CLASS,
            "getKey",
            "([BLjava/lang/String;)[B",
        ) {
            Ok(method) => {
                println!("FileKeyUnwrapper::new - static method ID obtained successfully");
                io::stdout().flush().expect("Failed to flush stdout");
                method
            },
            Err(e) => {
                println!("FileKeyUnwrapper::new - failed to get static method ID: {}", e);
                io::stdout().flush().expect("Failed to flush stdout");
                return Err(e);
            }
        };

        println!("FileKeyUnwrapper::new - initialization complete");
        io::stdout().flush().expect("Failed to flush stdout");

        Ok(FileKeyUnwrapper {
            method_get_key,
            method_get_key_ret: ReturnType::Array,
            class,
        })
    }
}