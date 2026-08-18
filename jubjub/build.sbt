ThisBuild / scalaVersion := "2.13.10"

val `scala-2.13`        = "2.13.10"
val sidechainsZkVersion = "0.0.6"

ThisBuild / version := sidechainsZkVersion

val rootDirectory = file(".")

sbtJniCoreScope := Compile

lazy val jubjubNative = project
  .in(file("jubjub-native"))
  .settings(
    name := "jubjub-native",
    nativeCompile / sourceDirectory := sourceDirectory.value / "native"
  )
  .enablePlugins(JniNative)

lazy val jubjubBindings = project
  .in(file("jubjub-bindings"))
  .settings(commonSettings("jubjub-bindings"))
  .settings(libraryDependencies ++= Dependencies.testing)
  .dependsOn(jubjubNative)

lazy val root = project
  .in(rootDirectory)
  .settings(
    name := "sidechains-zk"
  )
  .aggregate(
    jubjubNative,
    jubjubBindings
  )

val baseScalacOptions = Seq(
  "-unchecked",
  "-deprecation",
  "-feature",
  "-Wunused",
  "-encoding",
  "utf-8",
  "-Ymacro-annotations"
)

def commonSettings(projectName: String): Seq[sbt.Def.Setting[_]] = Seq(
  name := projectName,
  crossScalaVersions := List(`scala-2.13`),
  semanticdbEnabled := true,                        // enable SemanticDB
  semanticdbVersion := scalafixSemanticdb.revision, // use Scalafix compatible version
  IntegrationTest / parallelExecution := false,
  scalacOptions ++= baseScalacOptions,
  Compile / doc / sources := Nil,
  Compile / packageDoc / publishArtifact := false,
  libraryDependencies ++= Dependencies.betterMonadicFor,
  libraryDependencies += compilerPlugin(Dependencies.kindProjectorPlugin.cross(CrossVersion.full))
) ++
  inConfig(IntegrationTest)(Defaults.itSettings) ++
  inConfig(IntegrationTest)(org.scalafmt.sbt.ScalafmtPlugin.scalafmtConfigSettings) ++
  inConfig(IntegrationTest)(scalafixConfigSettings(IntegrationTest))

inThisBuild(
  List(
    organization := "io.iohk.sidechains",
    developers := List(
      Developer(
        id = "AmbientTea",
        name = "Nikolaos Dymitriadis",
        email = "nikolaos.dymitriadis@iohk.io",
        url = url("https://github.com/AmbientTea")
      )
    ),
    homepage := Some(url("https://github.com/input-output-hk")),
    scmInfo := Some(
      ScmInfo(
        url("https://github.com/input-output-hk/sidechains-zk"),
        "git@github.com:input-output-hk/sidechains-zk.git"
      )
    ),
    licenses := List("Apache-2.0" -> url("http://www.apache.org/licenses/LICENSE-2.0")),
    scalaVersion := `scala-2.13`,
    scalafixScalaBinaryVersion := CrossVersion.binaryScalaVersion(
      scalaVersion.value
    ),
    scalafixDependencies ++= List(
      "com.github.liancheng" %% "organize-imports" % "0.6.0",
      "com.github.vovapolu"  %% "scaluzzi"         % "0.1.23"
    )
  )
)

addCommandAlias(
  "validate",
  ";scalafmtSbtCheck;scalafmtCheckAll;scalafixAll --check;test;IntegrationTest/test"
)
