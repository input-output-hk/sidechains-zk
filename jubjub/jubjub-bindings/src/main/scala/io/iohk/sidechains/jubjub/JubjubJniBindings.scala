package io.iohk.sidechains.jubjub

import com.github.sbt.jni.syntax.NativeLoader

import scala.annotation.unused

class JubjubJniBindings extends NativeLoader("jubjub_zk") {
  @native def derivePublicKey(
      @unused privateKey: Bytes
  ): Bytes
  @native def sign(
      @unused data: Bytes,
      @unused key: Bytes
  ): Bytes
  @native def verify(
      @unused data: Bytes,
      @unused signature: Bytes,
      @unused publicKey: Bytes
  ): Boolean
  @native def createATMSProof(
      @unused data: Bytes,
      @unused signatures: Array[Bytes],
      @unused keys: Array[Bytes]
  ): Bytes
}
