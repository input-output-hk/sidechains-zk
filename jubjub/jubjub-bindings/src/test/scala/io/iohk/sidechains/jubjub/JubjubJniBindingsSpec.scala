package io.iohk.sidechains.jubjub

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class JubjubJniBindingsSpec extends AnyWordSpec with Matchers {

  val bindings = new JubjubJniBindings

  val sampleArray: Array[Byte] = Array[Byte](1, 2, 3)

  "JubJubJniBindings" should {
    "call native implementation of createKey" in {
      bindings.createKey() shouldBe Array.empty[Byte]
    }

    "call native implementation of sign" in {
      bindings.sign(sampleArray, sampleArray) shouldBe sampleArray
    }

    "call native implementation of createProof" in {
      bindings.createProof(sampleArray, Array(sampleArray), Array(sampleArray)) shouldBe sampleArray
    }
  }

}
