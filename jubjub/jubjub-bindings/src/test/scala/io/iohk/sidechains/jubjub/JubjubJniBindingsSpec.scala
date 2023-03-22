package io.iohk.sidechains.jubjub

import io.iohk.sidechains.Hex
import org.scalatest.EitherValues
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.util.Try

class JubjubJniBindingsSpec extends AnyWordSpec with Matchers with EitherValues {

  val bindings = new JubjubJniBindings

  val message: Array[Byte]  = Hex.decodeUnsafe("01234567890abcdef")
  val message2: Array[Byte] = Hex.decodeUnsafe("fedc456789000")

  val privateKey: Array[Byte] = Hex.decodeUnsafe(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
  )
  val publicKey: Array[Byte] = Hex.decodeUnsafe("f94c240b26cdb868cf6d56caa620612702d0294ae044acade84250d3eab653df")

  val privateKey2: Array[Byte] = Hex.decodeUnsafe(
    "fff1f2f3f4f5f6f7f8f9fafbfcfdfeff1f1112131415161718191a1b1c1d1e1f2f2122232425262728292a2b2c2d2e2f3f3132333435363738393a3b3c3d3e3f"
  )
  val publicKey2: Array[Byte] = Hex.decodeUnsafe("e8a335e943810f349af4b57fc87644367dea8dc1b6c6d804e3bf36d966d574ec")

  "JubJubJniBindings" should {
    "call native implementation of derivePublicKey" in {
      val derived = bindings.derivePublicKey(privateKey)
      assert(Hex.toHexString(derived) == Hex.toHexString(publicKey))
    }

    "fail derivePublicKey if key length is invalid" in {
      val message = Try(bindings.derivePublicKey(privateKey.drop(1))).toEither.swap.map(_.getMessage)
      assert(message.value == "private key length is invalid")
    }

    "pass of sign-verify round trip" in {
      val signature          = bindings.sign(message, privateKey)
      val verificationResult = bindings.verify(message, signature, publicKey);
      assert(verificationResult)
    }

    "fail verify if public key is invalid" in {
      val signature = bindings.sign(message, privateKey)
      val errMsg    = Try(bindings.verify(message, signature, Array.fill(32)(0.toByte))).toEither.swap.map(_.getMessage)
      assert(errMsg.value == "public key is invalid")
    }

    "fail not verify if public key doesn't match" in {
      val signature = bindings.sign(message, privateKey)
      val result    = bindings.verify(message, signature, publicKey2)
      assert(!result)
    }

    "not verify if message doesn't match" in {
      val signature = bindings.sign(message, privateKey)
      val result    = bindings.verify(message2, signature, publicKey)
      assert(!result)
    }

    "call native implementation of createProof happy-path" in {
      bindings.createATMSProof(message, Array(message), Array(message)) shouldBe message
    }
  }
}
