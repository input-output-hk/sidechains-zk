package io.iohk.sidechains;

object Hex {
  def toHexString(bytes: Iterable[Byte]): String =
    bytes.map("%02x".format(_)).mkString

  def decodeUnsafe(hex: String): Array[Byte] =
    hex.replaceFirst("^0x", "").toSeq.sliding(2, 2).toArray.map { s =>
      Integer.parseInt(s.mkString(""), 16).toByte
    }

}