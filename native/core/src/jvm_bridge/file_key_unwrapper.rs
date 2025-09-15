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

/// A struct that holds all the JNI methods and fields for JVM FileKeyUnwrapper object.
pub struct FileKeyUnwrapper<'a> {
    pub class: JClass<'a>,
    pub method_get_key: JStaticMethodID,
    pub method_get_key_ret: ReturnType,
}

impl<'a> FileKeyUnwrapper<'a> {
    pub const JVM_CLASS: &'static str = "org/apache/comet/parquet/crypto/CometFileKeyUnwrapper";

    pub fn new(env: &mut JNIEnv<'a>) -> JniResult<FileKeyUnwrapper<'a>> {
        let class = env.find_class(Self::JVM_CLASS)?;

        Ok(FileKeyUnwrapper {
            method_get_key: env.get_static_method_id(
                Self::JVM_CLASS,
                "getKey",
                "(Ljava/lang/String;[B)[B",
            )?,
            method_get_key_ret: ReturnType::Array,
            class,
        })
    }
}
