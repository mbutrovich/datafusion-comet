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

package org.apache.arrow.c;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.arrow.memory.ArrowBuf;
import org.apache.arrow.memory.BufferAllocator;
import org.apache.arrow.util.AutoCloseables;
import org.apache.arrow.util.VisibleForTesting;
import org.apache.arrow.vector.*;
import org.apache.arrow.vector.complex.*;
import org.apache.arrow.vector.ipc.message.ArrowFieldNode;
import org.apache.arrow.vector.types.pojo.ArrowType;
import org.apache.arrow.vector.util.DataSizeRoundingUtil;

import static org.apache.arrow.c.NativeUtil.NULL;
import static org.apache.arrow.util.Preconditions.checkState;

/**
 * Import buffers from a C Data Interface struct. We copy it from Arrow `BufferImportTypeVisitor`
 * and fix the issue: https://github.com/apache/arrow/issues/42156.
 */
class CometBufferImportTypeVisitor
    implements ArrowType.ArrowTypeVisitor<List<ArrowBuf>>, AutoCloseable {
  private final BufferAllocator allocator;
  private final ReferenceCountedArrowArray underlyingAllocation;
  private final ArrowFieldNode fieldNode;
  private final ArrowArray.Snapshot snapshot;
  private final long[] buffers;
  private final List<ArrowBuf> imported;

  CometBufferImportTypeVisitor(
      BufferAllocator allocator,
      ReferenceCountedArrowArray underlyingAllocation,
      ArrowFieldNode fieldNode,
      ArrowArray.Snapshot snapshot,
      long[] buffers) {
    this.allocator = allocator;
    this.underlyingAllocation = underlyingAllocation;
    this.fieldNode = fieldNode;
    this.snapshot = snapshot;
    this.buffers = buffers;
    this.imported = new ArrayList<>();
  }

  @Override
  public void close() throws Exception {
    AutoCloseables.close(imported);
  }

  @VisibleForTesting
  ArrowBuf importBuffer(ArrowType type, int index, long capacity) {
    return importBuffer(type, index, 0, capacity);
  }

  @VisibleForTesting
  ArrowBuf importBuffer(ArrowType type, int index, long offset, long capacity) {
    checkState(
        buffers.length > index,
        "Expected at least %s buffers for type %s, but found %s",
        index + 1,
        type,
        buffers.length);
    long bufferPtr = buffers[index] + offset;

    if (bufferPtr == NULL) {
      // C array may be NULL but only accept that if expected capacity is zero too
      if (capacity != 0) {
        throw new IllegalStateException(
            String.format("Buffer %s for type %s cannot be null", index, type));
      } else {
        // no data in the C array, return an empty buffer
        return allocator.getEmpty();
      }
    }

    ArrowBuf buf = underlyingAllocation.unsafeAssociateAllocation(allocator, capacity, bufferPtr);
    imported.add(buf);
    return buf;
  }

  private ArrowBuf importFixedBits(ArrowType type, int index, long bitsPerSlot) {
    final long capacity = DataSizeRoundingUtil.divideBy8Ceil(bitsPerSlot * fieldNode.getLength());
    return importBuffer(type, index, capacity);
  }

  private ArrowBuf importFixedBytes(ArrowType type, int index, long bytesPerSlot) {
    final long capacity = bytesPerSlot * fieldNode.getLength();
    return importBuffer(type, index, capacity);
  }

  private ArrowBuf importOffsets(ArrowType type, long bytesPerSlot) {
    final long capacity = bytesPerSlot * (fieldNode.getLength() + 1);
    final long offset = snapshot.offset * bytesPerSlot;
    return importBuffer(type, 1, offset, capacity);
  }

  private ArrowBuf importData(ArrowType type, long capacity) {
    return importBuffer(type, 2, capacity);
  }

  private ArrowBuf maybeImportBitmap(ArrowType type) {
    checkState(
        buffers.length > 0,
        "Expected at least %s buffers for type %s, but found %s",
        1,
        type,
        buffers.length);
    if (buffers[0] == NULL) {
      return null;
    }
    return importFixedBits(type, 0, /* bitsPerSlot= */ 1);
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Null type) {
    checkState(
        buffers.length == 0,
        "Expected %s buffers for type %s, but found %s",
        0,
        type,
        buffers.length);
    return Collections.emptyList();
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Struct type) {
    return Collections.singletonList(maybeImportBitmap(type));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.List type) {
    return Arrays.asList(maybeImportBitmap(type), importOffsets(type, ListVector.OFFSET_WIDTH));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.LargeList type) {
    return Arrays.asList(
        maybeImportBitmap(type), importOffsets(type, LargeListVector.OFFSET_WIDTH));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.FixedSizeList type) {
    return Collections.singletonList(maybeImportBitmap(type));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Union type) {
    switch (type.getMode()) {
      case Sparse:
        return Collections.singletonList(importFixedBytes(type, 0, UnionVector.TYPE_WIDTH));
      case Dense:
        return Arrays.asList(
            importFixedBytes(type, 0, DenseUnionVector.TYPE_WIDTH),
            importFixedBytes(type, 1, DenseUnionVector.OFFSET_WIDTH));
      default:
        throw new UnsupportedOperationException("Importing buffers for union type: " + type);
    }
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.RunEndEncoded type) {
    return List.of();
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Map type) {
    return Arrays.asList(maybeImportBitmap(type), importOffsets(type, MapVector.OFFSET_WIDTH));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Int type) {
    return Arrays.asList(maybeImportBitmap(type), importFixedBits(type, 1, type.getBitWidth()));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.FloatingPoint type) {
    switch (type.getPrecision()) {
      case HALF:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, /* bytesPerSlot= */ 2));
      case SINGLE:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, Float4Vector.TYPE_WIDTH));
      case DOUBLE:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, Float8Vector.TYPE_WIDTH));
      default:
        throw new UnsupportedOperationException("Importing buffers for type: " + type);
    }
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Utf8 type) {
    try (ArrowBuf offsets = importOffsets(type, VarCharVector.OFFSET_WIDTH)) {
      final int start = offsets.getInt(0);
      final int end = offsets.getInt(fieldNode.getLength() * (long) VarCharVector.OFFSET_WIDTH);
      checkState(
          end >= start,
          "Offset buffer for type %s is malformed: start: %s, end: %s",
          type,
          start,
          end);
      // HACK: For the issue https://github.com/apache/datafusion-comet/issues/540
      // As Arrow Java doesn't support `offset` in C Data interface, we cannot correctly import
      // a slice of string from arrow-rs to Java Arrow and then export it to arrow-rs again.
      // So we add this hack to always take full length of data buffer by assuming the first offset
      // is always 0 which is true for Arrow Java and arrow-rs.
      final int len = end;
      offsets.getReferenceManager().retain();
      return Arrays.asList(maybeImportBitmap(type), offsets, importData(type, len));
    }
  }

  private List<ArrowBuf> visitVariableWidthView(ArrowType type) {
    final int viewBufferIndex = 1;
    final int variadicSizeBufferIndex = this.buffers.length - 1;
    final long numOfVariadicBuffers = this.buffers.length - 3L;
    final long variadicSizeBufferCapacity = numOfVariadicBuffers * Long.BYTES;
    List<ArrowBuf> buffers = new ArrayList<>();

    // TODO: Figure out the offset hack for this visit function.

    ArrowBuf variadicSizeBuffer =
        importBuffer(type, variadicSizeBufferIndex, variadicSizeBufferCapacity);

    ArrowBuf view =
        importFixedBytes(type, viewBufferIndex, BaseVariableWidthViewVector.ELEMENT_SIZE);
    buffers.add(maybeImportBitmap(type));
    buffers.add(view);

    // 0th buffer is validity buffer
    // 1st buffer is view buffer
    // 2nd buffer onwards are variadic buffer
    // N-1 (this.buffers.length - 1) buffer is variadic size buffer
    final int variadicBufferReadOffset = 2;
    for (int i = 0; i < numOfVariadicBuffers; i++) {
      long size = variadicSizeBuffer.getLong((long) i * Long.BYTES);
      buffers.add(importBuffer(type, i + variadicBufferReadOffset, size));
    }

    return buffers;
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Utf8View type) {
    return visitVariableWidthView(type);
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.LargeUtf8 type) {
    try (ArrowBuf offsets = importOffsets(type, LargeVarCharVector.OFFSET_WIDTH)) {
      final long start = offsets.getLong(0);
      final long end =
          offsets.getLong(fieldNode.getLength() * (long) LargeVarCharVector.OFFSET_WIDTH);
      checkState(
          end >= start,
          "Offset buffer for type %s is malformed: start: %s, end: %s",
          type,
          start,
          end);
      // HACK: For the issue https://github.com/apache/datafusion-comet/issues/540
      // As Arrow Java doesn't support `offset` in C Data interface, we cannot correctly import
      // a slice of string from arrow-rs to Java Arrow and then export it to arrow-rs again.
      // So we add this hack to always take full length of data buffer by assuming the first offset
      // is always 0 which is true for Arrow Java and arrow-rs.
      final long len = end;
      offsets.getReferenceManager().retain();
      return Arrays.asList(maybeImportBitmap(type), offsets, importData(type, len));
    }
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Binary type) {
    try (ArrowBuf offsets = importOffsets(type, VarBinaryVector.OFFSET_WIDTH)) {
      final int start = offsets.getInt(0);
      final int end = offsets.getInt(fieldNode.getLength() * (long) VarBinaryVector.OFFSET_WIDTH);
      checkState(
          end >= start,
          "Offset buffer for type %s is malformed: start: %s, end: %s",
          type,
          start,
          end);
      // HACK: For the issue https://github.com/apache/datafusion-comet/issues/540
      // As Arrow Java doesn't support `offset` in C Data interface, we cannot correctly import
      // a slice of string from arrow-rs to Java Arrow and then export it to arrow-rs again.
      // So we add this hack to always take full length of data buffer by assuming the first offset
      // is always 0 which is true for Arrow Java and arrow-rs.
      final int len = end;
      offsets.getReferenceManager().retain();
      return Arrays.asList(maybeImportBitmap(type), offsets, importData(type, len));
    }
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.BinaryView type) {
    return visitVariableWidthView(type);
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.LargeBinary type) {
    try (ArrowBuf offsets = importOffsets(type, LargeVarBinaryVector.OFFSET_WIDTH)) {
      final long start = offsets.getLong(0);
      // TODO: need better tests to cover the failure when I forget to multiply by offset width
      final long end =
          offsets.getLong(fieldNode.getLength() * (long) LargeVarBinaryVector.OFFSET_WIDTH);
      checkState(
          end >= start,
          "Offset buffer for type %s is malformed: start: %s, end: %s",
          type,
          start,
          end);
      // HACK: For the issue https://github.com/apache/datafusion-comet/issues/540
      // As Arrow Java doesn't support `offset` in C Data interface, we cannot correctly import
      // a slice of string from arrow-rs to Java Arrow and then export it to arrow-rs again.
      // So we add this hack to always take full length of data buffer by assuming the first offset
      // is always 0 which is true for Arrow Java and arrow-rs.
      final long len = end;
      offsets.getReferenceManager().retain();
      return Arrays.asList(maybeImportBitmap(type), offsets, importData(type, len));
    }
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.FixedSizeBinary type) {
    return Arrays.asList(maybeImportBitmap(type), importFixedBytes(type, 1, type.getByteWidth()));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Bool type) {
    return Arrays.asList(maybeImportBitmap(type), importFixedBits(type, 1, /* bitsPerSlot= */ 1));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Decimal type) {
    return Arrays.asList(maybeImportBitmap(type), importFixedBits(type, 1, type.getBitWidth()));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Date type) {
    switch (type.getUnit()) {
      case DAY:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, DateDayVector.TYPE_WIDTH));
      case MILLISECOND:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, DateMilliVector.TYPE_WIDTH));
      default:
        throw new UnsupportedOperationException("Importing buffers for type: " + type);
    }
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Time type) {
    switch (type.getUnit()) {
      case SECOND:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, TimeSecVector.TYPE_WIDTH));
      case MILLISECOND:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, TimeMilliVector.TYPE_WIDTH));
      case MICROSECOND:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, TimeMicroVector.TYPE_WIDTH));
      case NANOSECOND:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, TimeNanoVector.TYPE_WIDTH));
      default:
        throw new UnsupportedOperationException("Importing buffers for type: " + type);
    }
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Timestamp type) {
    return Arrays.asList(
        maybeImportBitmap(type), importFixedBytes(type, 1, TimeStampVector.TYPE_WIDTH));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Interval type) {
    switch (type.getUnit()) {
      case YEAR_MONTH:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, IntervalYearVector.TYPE_WIDTH));
      case DAY_TIME:
        return Arrays.asList(
            maybeImportBitmap(type), importFixedBytes(type, 1, IntervalDayVector.TYPE_WIDTH));
      case MONTH_DAY_NANO:
        return Arrays.asList(
            maybeImportBitmap(type),
            importFixedBytes(type, 1, IntervalMonthDayNanoVector.TYPE_WIDTH));
      default:
        throw new UnsupportedOperationException("Importing buffers for type: " + type);
    }
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.Duration type) {
    return Arrays.asList(
        maybeImportBitmap(type), importFixedBytes(type, 1, DurationVector.TYPE_WIDTH));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.ListView type) {
    return Arrays.asList(
        maybeImportBitmap(type),
        importFixedBytes(type, 1, ListViewVector.OFFSET_WIDTH),
        importFixedBytes(type, 2, ListViewVector.SIZE_WIDTH));
  }

  @Override
  public List<ArrowBuf> visit(ArrowType.LargeListView type) {
    return Arrays.asList(
        maybeImportBitmap(type),
        importFixedBytes(type, 1, LargeListViewVector.OFFSET_WIDTH),
        importFixedBytes(type, 2, LargeListViewVector.SIZE_WIDTH));
  }
}
