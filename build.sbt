ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "2.13.10"

val `scala-2.13`        = "2.13.10"
val sidechainsZkVersion = "0.0.1"

val rootDirectory = file(".")

lazy val root = project
  .in(rootDirectory)

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
  version := sidechainsZkVersion,
  crossScalaVersions := List(`scala-2.13`),
  semanticdbEnabled := true,                        // enable SemanticDB
  semanticdbVersion := scalafixSemanticdb.revision, // use Scalafix compatible version
  IntegrationTest / parallelExecution := false,
  scalacOptions ++= baseScalacOptions,
  Compile / doc / sources := Nil,
  Compile / packageDoc / publishArtifact := false,
  libraryDependencies ++= Dependencies.betterMonadicFor,
  libraryDependencies += compilerPlugin(Dependencies.kindProjectorPlugin.cross(CrossVersion.full)),
  // Only publish selected libraries.
  publish / skip := true
) ++
  inConfig(IntegrationTest)(Defaults.itSettings) ++
  inConfig(IntegrationTest)(org.scalafmt.sbt.ScalafmtPlugin.scalafmtConfigSettings) ++
  inConfig(IntegrationTest)(scalafixConfigSettings(IntegrationTest))
