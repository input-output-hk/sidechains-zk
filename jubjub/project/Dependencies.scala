import sbt._

object Dependencies {

  val betterMonadicFor: Seq[ModuleID] = Seq(compilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1"))
  val kindProjectorPlugin: ModuleID   = "org.typelevel" % "kind-projector" % "0.13.2"

  val testing: Seq[ModuleID] = Seq(
    "org.scalatest"          %% "scalatest"              % "3.2.15",
    "org.scalatestplus"      %% "scalacheck-1-17"        % "3.2.15.0",
    "org.scalacheck"         %% "scalacheck"             % "1.17.0",
    "com.softwaremill.diffx" %% "diffx-scalatest-should" % "0.8.2"
  ).map(_ % Test)
}
