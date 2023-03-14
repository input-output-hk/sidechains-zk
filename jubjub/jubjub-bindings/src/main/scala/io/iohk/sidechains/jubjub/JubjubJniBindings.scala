package io.iohk.sidechains.jubjub

import com.github.sbt.jni.syntax.NativeLoader

import scala.annotation.unused

class JubjubJniBindings extends NativeLoader("jubjub_zk") {
  @native def createKey(): Bytes
  @native def sign(
      @unused data: Bytes,
      @unused key: Bytes
  ): Bytes
  @native def createProof(
      @unused data: Bytes,
      @unused signatures: Array[Bytes],
      @unused keys: Array[Bytes]
  ): Bytes
}
